use {
    anyhow::Result,
    capnp::{self, message::ReaderOptions},
    clap::Parser,
    im::HashMap as ImHashMap,
    itertools::Itertools,
    log::*,
    solana_runtime::{
        account_storage::{
            meta::StoredMetaWriteVersion, AccountStorageMap, AccountStorageReference,
        },
        accounts_db::{
            AccountShrinkThreshold, AccountStorageEntry, AtomicAppendVecId, BankHashStats,
            CalcAccountsHashDataSource,
        },
        accounts_file::AccountsFile,
        accounts_hash::{AccountsDeltaHash, AccountsHash},
        accounts_index::AccountSecondaryIndexes,
        ancestors::AncestorsForSerialization,
        bank::{
            Bank, BankFieldsToDeserialize, EpochRewardStatus, RewardInfo, StakeReward,
            StartBlockHeightAndRewards,
        },
        blockhash_queue::{BlockhashQueue, HashAge},
        epoch_stakes::{EpochStakes, NodeVoteAccounts},
        hardened_unpack::open_genesis_config,
        rent_collector::RentCollector,
        runtime_config::RuntimeConfig,
        serde_snapshot::{
            self,
            storage::SerializableAccountStorageEntry,
            types::{SerdeAccountsHash, SerdeIncrementalAccountsHash},
            AccountsDbFields, BankIncrementalSnapshotPersistence, SnapshotAccountsDbFields,
        },
        snapshot_utils::{self, StorageAndNextAppendVecId},
        stake_history::StakeHistory,
        stakes::{Stakes, StakesEnum},
        vote_account::VoteAccountsHashMap,
    },
    solana_sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        clock::Slot,
        epoch_schedule::{Epoch, EpochSchedule},
        fee_calculator::{FeeCalculator, FeeRateGovernor},
        genesis_config::GenesisConfig,
        hard_forks::HardForks,
        hash::Hash,
        inflation::Inflation,
        pubkey::Pubkey,
        rent::Rent,
        reward_type::RewardType,
        stake::state::Delegation,
        stake_history::StakeHistoryEntry,
    },
    std::{collections::HashMap, io::BufReader, path::PathBuf, sync::Arc, time::Instant},
    tempfile::TempDir,
};

mod snapshot_capnp {
    #![allow(dead_code)]
    include!(concat!(env!("OUT_DIR"), "/schema/snapshot_capnp.rs"));
}

#[derive(Debug, Parser)]
struct Cli {
    /// Path to the ledger directory
    ledger_dir: Option<PathBuf>,
    /// Use a packed encoding for the snapshot
    #[arg(long)]
    packed: bool,
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();
    debug!("{cli:?}");

    info!("Loading bank...");
    let temp_accounts_dir = TempDir::new()?;
    let timer = Instant::now();
    let (bank, genesis_config, account_paths) = {
        if let Some(ledger_dir) = &cli.ledger_dir {
            let bank_snapshots_dir = ledger_dir.join("snapshot");
            let accounts_dir = ledger_dir.join("accounts");
            let account_paths = [accounts_dir];
            let genesis_config = open_genesis_config(&ledger_dir, u64::MAX);

            /* NOTE: Fastboot is broken in v1.16
             * snapshot_utils::bank_from_latest_snapshot_dir(
             *     bank_snapshots_dir,
             *     &genesis_config,
             *     &RuntimeConfig::default(),
             *     &[accounts_dir],
             *     None,
             *     None,
             *     AccountSecondaryIndexes::default(),
             *     None,
             *     AccountShrinkThreshold::default(),
             *     false,
             *     None,
             *     None,
             *     &Arc::default(),
             * )?
             */

            let (bank, ..) = snapshot_utils::bank_from_latest_snapshot_archives(
                bank_snapshots_dir,
                &ledger_dir,
                &ledger_dir,
                &account_paths,
                &genesis_config,
                &RuntimeConfig::default(),
                None,
                None,
                AccountSecondaryIndexes::default(),
                None,
                AccountShrinkThreshold::default(),
                false,
                true,
                false,
                None,
                None,
                &Arc::default(),
            )?;
            (bank, genesis_config, account_paths)
        } else {
            let account_paths = [temp_accounts_dir.path().to_path_buf()];
            let genesis_config = GenesisConfig::default();
            let mut bank = Arc::new(Bank::new_with_paths_for_tests(
                &genesis_config,
                RuntimeConfig::default().into(),
                account_paths.to_vec(),
                AccountSecondaryIndexes::default(),
                AccountShrinkThreshold::default(),
            ));
            for _ in 0..21 {
                bank = Arc::new(Bank::new_from_parent(
                    &bank,
                    &Pubkey::new_unique(),
                    bank.slot() + 1,
                ));
                bank.fill_bank_with_ticks_for_tests();
            }
            let bank = Arc::into_inner(bank).unwrap();
            bank.squash();
            bank.force_flush_accounts_cache();
            bank.update_accounts_hash(CalcAccountsHashDataSource::Storages, false, false);
            (bank, genesis_config, account_paths)
        }
    };
    info!("Loading bank... Done, and took {:?}", timer.elapsed());

    let snapshot_storages = bank.get_snapshot_storages(None);

    info!("Taking snapshot...");
    let timer = Instant::now();
    let serialized_snapshot = snapshot_bank(&bank, &snapshot_storages, cli.packed)?;
    info!("Taking snapshot... Done, and took {:?}", timer.elapsed());

    info!("Rebuilding from snapshot...");
    let timer = Instant::now();
    let deserialized_bank = rebuild_bank(
        serialized_snapshot,
        &genesis_config,
        &account_paths,
        &snapshot_storages,
        cli.packed,
    )?;
    info!(
        "Rebuilding from snapshot... Done, and took {:?}",
        timer.elapsed()
    );

    assert_eq!(deserialized_bank.slot(), bank.slot());
    assert_eq!(deserialized_bank.hash(), bank.hash());

    info!("Success!");
    Ok(())
}

fn snapshot_bank(
    bank: &Bank,
    snapshot_storages: &[Arc<AccountStorageEntry>],
    packed: bool,
) -> Result<Vec<u8>> {
    let ancestors_for_bank_fields = HashMap::<Slot, usize>::from(&bank.ancestors); // TODO: it would be nice to not make a copy
    let bank_fields = bank.get_fields_to_serialize(&ancestors_for_bank_fields);

    // ALT: let mut message = capnp::message::Builder::new_default();
    let mut message =
        capnp::message::TypedBuilder::<snapshot_capnp::snapshot::Owned>::new_default();
    {
        // ALT: let mut snapshot_builder = message.init_root::<snapshot_capnp::snapshot::Builder>();
        let mut snapshot_builder = message.init_root();
        {
            let mut bank_builder = snapshot_builder.reborrow().init_bank();
            bank_builder.set_block_height(bank_fields.block_height);
            bank_builder.set_epoch(bank_fields.epoch);
            bank_builder.set_slot(bank_fields.slot);
            bank_builder.reborrow().init_hash().set(&bank_fields.hash);

            if let Some(epoch_accounts_hash) = bank.get_epoch_accounts_hash_to_serialize() {
                bank_builder
                    .reborrow()
                    .init_epoch_accounts_hash()
                    .set(epoch_accounts_hash.as_ref());
            }

            bank_builder.set_parent_slot(bank_fields.parent_slot);
            bank_builder
                .reborrow()
                .init_parent_hash()
                .set(&bank.parent_hash());
            bank_builder.set_transaction_count(bank_fields.transaction_count);
            bank_builder.set_tick_height(bank_fields.tick_height);
            bank_builder.set_max_tick_height(bank_fields.max_tick_height);

            if let Some(hashes_per_tick) = bank_fields.hashes_per_tick {
                bank_builder
                    .reborrow()
                    .init_hashes_per_tick()
                    .set_some(hashes_per_tick);
            } else {
                bank_builder.reborrow().init_hashes_per_tick().set_none(());
            }

            bank_builder.set_ticks_per_slot(bank_fields.ticks_per_slot);
            bank_builder.set_ns_per_slot(
                bank_fields
                    .ns_per_slot
                    .try_into()
                    .expect("ns_per_slot <= u64::MAX"),
            );
            bank_builder.set_slots_per_year(bank_fields.slots_per_year);
            bank_builder.set_signature_count(bank_fields.signature_count);
            bank_builder.set_capitalization(bank_fields.capitalization);
            bank_builder.set_is_delta(bank_fields.is_delta);
            bank_builder.set_accounts_data_size(bank_fields.accounts_data_len);
            bank_builder
                .reborrow()
                .init_collector_id()
                .set(&bank_fields.collector_id);
            bank_builder.set_collector_fees(bank_fields.collector_fees);
            bank_builder.set_collected_rent(bank_fields.collected_rent);
            bank_builder.set_genesis_creation_time(
                bank_fields
                    .genesis_creation_time
                    .try_into()
                    .expect("genesis creation time is positive"),
            );

            bank_builder
                .reborrow()
                .init_inflation()
                .set(&bank_fields.inflation);

            {
                let hard_forks = bank_fields.hard_forks.read().unwrap();
                let mut hard_forks_builder = bank_builder
                    .reborrow()
                    .init_hard_forks(hard_forks.iter().len().try_into()?);
                for (i, hard_fork) in hard_forks.iter().enumerate() {
                    let mut hard_fork_builder = hard_forks_builder.reborrow().get(i as u32);
                    hard_fork_builder.set_slot(hard_fork.0);
                    hard_fork_builder.set_count(hard_fork.1 as u64);
                }
            }

            bank_builder
                .reborrow()
                .init_fee_rate_governor()
                .set(&bank_fields.fee_rate_governor);

            if let Some(incremental_snapshot_persistence) =
                bank.incremental_snapshot_persistence.as_ref()
            {
                bank_builder
                    .reborrow()
                    .init_incremental_snapshot_persistence()
                    .set(incremental_snapshot_persistence);
            }

            bank_builder
                .reborrow()
                .init_rent_collector()
                .set(&bank_fields.rent_collector);

            {
                let mut ancestors_builders = bank_builder
                    .reborrow()
                    .init_ancestors(bank_fields.ancestors.len().try_into()?);
                for (i, ancestor) in bank_fields.ancestors.keys().enumerate() {
                    ancestors_builders.reborrow().set(i as u32, *ancestor);
                }
            }

            bank_builder
                .reborrow()
                .init_epoch_schedule()
                .set(&bank_fields.epoch_schedule);

            {
                let blockhash_queue = bank_fields.blockhash_queue.read().unwrap();
                bank_builder
                    .reborrow()
                    .init_blockhash_queue()
                    .set(&blockhash_queue);
            }

            {
                let stakes =
                    Stakes::<Delegation>::from(bank_fields.stakes.0.read().unwrap().clone());
                bank_builder.reborrow().init_stakes().set(&stakes);
            }

            {
                let mut epoch_stakes_builder = bank_builder
                    .reborrow()
                    .init_epoch_stakes(bank_fields.epoch_stakes.len().try_into()?);
                for (i, (epoch, epoch_stake)) in bank_fields.epoch_stakes.iter().enumerate() {
                    let mut epoch_stake_builder = epoch_stakes_builder.reborrow().get(i as u32);
                    epoch_stake_builder.set(*epoch, epoch_stake);
                }
            }
        }

        let slot = bank.slot();
        let accounts_db = &bank.rc.accounts.accounts_db;

        snapshot_builder
            .reborrow()
            .init_accounts_delta_hash()
            .set(&accounts_db.get_accounts_delta_hash(slot).unwrap().0);

        if let Some(accounts_hash) = accounts_db.get_accounts_hash(slot) {
            snapshot_builder
                .reborrow()
                .init_accounts_hash()
                .set(&accounts_hash.0 .0);
        }

        {
            let mut account_storages_builder = snapshot_builder
                .reborrow()
                .init_account_storages(snapshot_storages.len().try_into()?);
            for (i, account_storage) in snapshot_storages.iter().enumerate() {
                let mut account_storage_builder = account_storages_builder.reborrow().get(i as u32);
                account_storage_builder.set_slot(account_storage.slot());
                account_storage_builder.set_id(account_storage.append_vec_id());
                account_storage_builder.set_count(account_storage.count() as u64);
            }
        }
    }

    let mut buffer = Vec::new();
    if packed {
        // ALT: capnp::serialize_packed::write_message(&mut buffer, &message)?;
        capnp::serialize_packed::write_message(&mut buffer, message.borrow_inner())?;
    } else {
        capnp::serialize::write_message(&mut buffer, message.borrow_inner())?;
    }
    info!(
        "Snapshot size: {} bytes {}",
        buffer.len(),
        if packed { "(packed)" } else { "" }
    );
    Ok(buffer)
}

fn rebuild_bank(
    serialized_snapshot: Vec<u8>,
    genesis_config: &GenesisConfig,
    account_paths: &[PathBuf],
    snapshot_storages: &[Arc<AccountStorageEntry>],
    packed: bool,
) -> Result<Bank> {
    let mut reader_options = ReaderOptions::default();
    reader_options.traversal_limit_in_words(None); // TODO: real impl should have a limit
    info!("Loading snapshot...");
    let timer = Instant::now();
    let reader = if packed {
        capnp::serialize_packed::read_message(
            BufReader::new(serialized_snapshot.as_slice()),
            reader_options,
        )
    } else {
        capnp::serialize::read_message(
            BufReader::new(serialized_snapshot.as_slice()),
            reader_options,
        )
    }?;
    let typed_reader =
        capnp::message::TypedReader::<_, snapshot_capnp::snapshot::Owned>::new(reader);
    let snapshot_reader = typed_reader.get()?;
    info!("Loading snapshot... Done, and took {:?}", timer.elapsed());
    trace!("deserialized snapshot: {snapshot_reader:#?}");

    info!("Getting fields from snapshot...");
    let timer = Instant::now();
    let bank_reader = snapshot_reader.get_bank()?;
    let epoch_stakes_reader = bank_reader.get_epoch_stakes()?;
    let mut epoch_stakes = HashMap::with_capacity(epoch_stakes_reader.len().try_into()?);
    for epoch_stake_reader in epoch_stakes_reader.iter() {
        let stakes = epoch_stake_reader.get_stakes()?.get()?;
        let total_stake = epoch_stake_reader.get_total_stake();

        let node_ids_to_vote_accounts_reader =
            epoch_stake_reader.get_node_ids_to_vote_accounts()?;
        let mut node_ids_to_vote_accounts =
            HashMap::with_capacity(node_ids_to_vote_accounts_reader.len().try_into()?);
        for node_id_to_vote_accounts_reader in node_ids_to_vote_accounts_reader.iter() {
            let total_stake = node_id_to_vote_accounts_reader.get_total_stake();

            let vote_accounts_reader = node_id_to_vote_accounts_reader.get_vote_accounts()?;
            let mut vote_accounts = Vec::with_capacity(vote_accounts_reader.len().try_into()?);
            for vote_account_reader in vote_accounts_reader.iter() {
                let pubkey = vote_account_reader.get()?;
                vote_accounts.push(pubkey);
            }

            let key = node_id_to_vote_accounts_reader.get_node_id()?.get()?;
            let value = NodeVoteAccounts {
                vote_accounts,
                total_stake,
            };
            let old_value = node_ids_to_vote_accounts.insert(key, value);
            assert!(
                old_value.is_none(),
                "key: {key:?}, old value: {old_value:?}"
            );
        }

        let epoch_authorized_voters_reader = epoch_stake_reader.get_epoch_authorized_voters()?;
        let mut epoch_authorized_voters =
            HashMap::with_capacity(epoch_authorized_voters_reader.len().try_into()?);
        for epoch_authorized_voter_reader in epoch_authorized_voters_reader.iter() {
            let key = epoch_authorized_voter_reader.get_vote_account()?.get()?;
            let value = epoch_authorized_voter_reader
                .get_authorized_voter()?
                .get()?;
            let old_value = epoch_authorized_voters.insert(key, value);
            assert!(
                old_value.is_none(),
                "key: {key:?}, value: {value:?}, old value: {old_value:?}"
            );
        }

        let key = epoch_stake_reader.get_epoch();
        let value = EpochStakes {
            stakes: Arc::new(stakes.into()),
            total_stake,
            node_id_to_vote_accounts: Arc::new(node_ids_to_vote_accounts),
            epoch_authorized_voters: Arc::new(epoch_authorized_voters),
        };
        let old_value = epoch_stakes.insert(key, value);
        assert!(
            old_value.is_none(),
            "key: {key:?}, old value: {old_value:?}"
        );
    }

    let bank_fields = serde_snapshot::SnapshotBankFields {
        full: BankFieldsToDeserialize {
            blockhash_queue: bank_reader.get_blockhash_queue()?.get()?,
            ancestors: AncestorsForSerialization::from_iter(
                bank_reader
                    .get_ancestors()?
                    .iter()
                    .map(|slot| (slot, /*unused*/ usize::default())),
            ),
            hash: bank_reader.get_hash()?.get()?,
            parent_hash: bank_reader.get_parent_hash()?.get()?,
            parent_slot: bank_reader.get_parent_slot(),
            hard_forks: HardForks {
                hard_forks: bank_reader
                    .get_hard_forks()?
                    .iter()
                    .map(|hard_fork_reader| {
                        (
                            hard_fork_reader.get_slot(),
                            hard_fork_reader.get_count() as usize,
                        )
                    })
                    .sorted_unstable()
                    .collect(),
            },
            transaction_count: bank_reader.get_transaction_count(),
            tick_height: bank_reader.get_tick_height(),
            signature_count: bank_reader.get_signature_count(),
            capitalization: bank_reader.get_capitalization(),
            max_tick_height: bank_reader.get_max_tick_height(),
            hashes_per_tick: match bank_reader.get_hashes_per_tick().which()? {
                snapshot_capnp::bank::hashes_per_tick::Which::None(..) => None,
                snapshot_capnp::bank::hashes_per_tick::Which::Some(val) => Some(val),
            },
            ticks_per_slot: bank_reader.get_ticks_per_slot(),
            ns_per_slot: bank_reader.get_ns_per_slot().into(),
            genesis_creation_time: bank_reader.get_genesis_creation_time().try_into()?,
            slots_per_year: bank_reader.get_slots_per_year(),
            slot: bank_reader.get_slot(),
            epoch: bank_reader.get_epoch(),
            block_height: bank_reader.get_block_height(),
            collector_id: bank_reader.get_collector_id()?.get()?,
            collector_fees: bank_reader.get_collector_fees(),
            fee_calculator: FeeCalculator::default(), // unused
            fee_rate_governor: bank_reader.get_fee_rate_governor()?.get(),
            collected_rent: bank_reader.get_collected_rent(),
            rent_collector: bank_reader.get_rent_collector()?.get()?,
            epoch_schedule: bank_reader.get_epoch_schedule()?.get(),
            inflation: bank_reader.get_inflation()?.get(),
            stakes: bank_reader.get_stakes()?.get()?,
            epoch_stakes,
            is_delta: bank_reader.get_is_delta(),
            accounts_data_len: bank_reader.get_accounts_data_size(),
            incremental_snapshot_persistence: bank_reader
                .get_incremental_snapshot_persistence()?
                .map(|reader| reader.get().unwrap()), // TODO: replace unwrap
            epoch_accounts_hash: bank_reader
                .get_epoch_accounts_hash()?
                .map(|reader| reader.get().unwrap()), // TODO: replace unwrap
            epoch_reward_status: match bank_reader.get_epoch_rewards()? {
                None => EpochRewardStatus::Inactive,
                Some(epoch_rewards_reader) => {
                    EpochRewardStatus::Active(epoch_rewards_reader.get()?)
                }
            },
        },
        incremental: None,
    };
    let storages_map = HashMap::from_iter(snapshot_reader.get_account_storages()?.iter().map(
        |account_storage| {
            (
                account_storage.get_slot(),
                vec![SerializableAccountStorageEntry {
                    id: account_storage.get_id() as usize,
                    accounts_current_len: account_storage.get_count() as usize,
                }],
            )
        },
    ));
    let accounts_db_fields = AccountsDbFields(
        storages_map,
        StoredMetaWriteVersion::default(), // value shouldn't matter
        bank_reader.get_slot(),
        serde_snapshot::BankHashInfo {
            accounts_delta_hash: AccountsDeltaHash(Hash::new(
                snapshot_reader.get_accounts_delta_hash()?.get_bytes()?,
            ))
            .into(),
            accounts_hash: AccountsHash(
                snapshot_reader
                    .get_accounts_hash()?
                    .map(|accounts_hash_reader| {
                        Hash::new(accounts_hash_reader.get_bytes().unwrap())
                    })
                    .unwrap_or_else(Hash::default),
            )
            .into(),
            stats: BankHashStats::default(), // value shouldn't matter
        },
        Vec::default(), // unused: was for historical roots
        Vec::default(), // unused: was for historical roots with hash
    );
    let accounts_db_fields = SnapshotAccountsDbFields {
        full_snapshot_accounts_db_fields: accounts_db_fields,
        incremental_snapshot_accounts_db_fields: None,
    };

    let storages = AccountStorageMap::with_capacity(snapshot_storages.len());
    for snapshot_storage in snapshot_storages {
        let slot = snapshot_storage.slot();
        let append_vec_id = snapshot_storage.append_vec_id();

        let (accounts_file, num_accounts) = AccountsFile::new_from_file(
            &snapshot_storage.get_path(),
            snapshot_storage.written_bytes() as usize,
        )?;
        let account_storage_entry =
            AccountStorageEntry::new_existing(slot, append_vec_id, accounts_file, num_accounts);

        let key = slot;
        let value = AccountStorageReference {
            storage: account_storage_entry.into(),
            id: append_vec_id,
        };
        let old_value = storages.insert(key, value);
        assert!(
            old_value.is_none(),
            "key: {key:?}, old value: {old_value:?}"
        );
    }
    let storage_and_next_append_vec_id = StorageAndNextAppendVecId {
        storage: storages,
        next_append_vec_id: AtomicAppendVecId::new((snapshot_storages.len() + 1).try_into()?),
    };
    info!(
        "Getting fields from snapshot... Done, and took {:?}",
        timer.elapsed()
    );

    info!("Reconstructing bank from fields...");
    let timer = Instant::now();
    let bank = serde_snapshot::reconstruct_bank_from_fields(
        bank_fields,
        accounts_db_fields,
        genesis_config,
        &RuntimeConfig::default(),
        account_paths,
        storage_and_next_append_vec_id,
        None,
        None,
        AccountSecondaryIndexes::default(),
        None,
        AccountShrinkThreshold::default(),
        false,
        None,
        None,
        &Arc::new(false.into()),
    )?;
    info!(
        "Reconstructing bank from fields... Done, and took {:?}",
        timer.elapsed()
    );

    Ok(bank)
}

impl<'a> snapshot_capnp::hash::Builder<'a> {
    fn set(&mut self, hash: &Hash) {
        self.set_bytes(&hash.to_bytes());
    }
}
impl<'a> snapshot_capnp::hash::Reader<'a> {
    fn get(&self) -> Result<Hash> {
        let bytes = self.get_bytes()?;
        assert_eq!(bytes.len(), std::mem::size_of::<Hash>());
        Ok(Hash::new(bytes))
    }
}

impl<'a> snapshot_capnp::pubkey::Builder<'a> {
    fn set(&mut self, pubkey: &Pubkey) {
        self.set_bytes(&pubkey.to_bytes());
    }
}
impl<'a> snapshot_capnp::pubkey::Reader<'a> {
    fn get(&self) -> Result<Pubkey> {
        let bytes = self.get_bytes()?;
        assert_eq!(bytes.len(), std::mem::size_of::<Pubkey>());
        Ok(Pubkey::try_from(bytes)?)
    }
}

impl<'a> snapshot_capnp::account::Builder<'a> {
    fn set(&mut self, account: impl ReadableAccount) {
        self.set_lamports(account.lamports());
        self.set_data(account.data());
        self.reborrow().init_owner().set(account.owner());
        self.set_executable(account.executable());
        self.set_rent_epoch(account.rent_epoch());
    }
}
impl<'a> snapshot_capnp::account::Reader<'a> {
    fn get<A: WritableAccount>(&self) -> Result<A> {
        let lamports = self.get_lamports();
        let data = self.get_data()?.to_vec();
        let owner = self.get_owner()?.get()?;
        let executable = self.get_executable();
        let rent_epoch = self.get_rent_epoch();

        Ok(A::create(lamports, data, owner, executable, rent_epoch))
    }
}

impl<'a> snapshot_capnp::blockhash_queue::Builder<'a> {
    fn set(&mut self, blockhash_queue: &BlockhashQueue) {
        self.set_last_hash_index(blockhash_queue.last_hash_index);
        blockhash_queue
            .last_hash
            .as_ref()
            .map(|last_hash| self.reborrow().init_last_hash().set(last_hash));
        self.set_max_age(blockhash_queue.max_age.try_into().unwrap());
        let mut ages_builder = self
            .reborrow()
            .init_ages(blockhash_queue.ages.len().try_into().unwrap());
        for (i, age) in blockhash_queue.ages.iter().enumerate() {
            let mut age_builder = ages_builder.reborrow().get(i as u32);
            age_builder.reborrow().init_hash().set(&age.0);
            age_builder.set_hash_index(age.1.hash_index);
            age_builder.set_timestamp(age.1.timestamp);
            age_builder.init_fee_calculator().set(&age.1.fee_calculator);
        }
    }
}
impl<'a> snapshot_capnp::blockhash_queue::Reader<'a> {
    fn get(&self) -> Result<BlockhashQueue> {
        let ages_reader = self.get_ages()?;
        let mut ages = HashMap::with_capacity(ages_reader.len().try_into()?);
        for age_reader in ages_reader {
            let key = age_reader.get_hash()?.get()?;
            let value = HashAge {
                hash_index: age_reader.get_hash_index(),
                timestamp: age_reader.get_timestamp(),
                fee_calculator: age_reader.get_fee_calculator()?.get(),
            };
            let old_value = ages.insert(key, value);
            assert!(
                old_value.is_none(),
                "key: {key:?}, old value: {old_value:?}"
            ); // TODO: this could be an error instead
        }

        Ok(BlockhashQueue {
            last_hash_index: self.get_last_hash_index(),
            last_hash: self.get_last_hash()?.map(|reader| reader.get().unwrap()), // TODO: remove unwrap
            max_age: self.get_max_age().try_into()?,
            ages,
        })
    }
}

impl<'a> snapshot_capnp::fee_calculator::Builder<'a> {
    fn set(&mut self, fee_calculator: &FeeCalculator) {
        self.set_lamports_per_signature(fee_calculator.lamports_per_signature);
    }
}
impl<'a> snapshot_capnp::fee_calculator::Reader<'a> {
    fn get(&self) -> FeeCalculator {
        FeeCalculator {
            lamports_per_signature: self.get_lamports_per_signature(),
        }
    }
}

impl<'a> snapshot_capnp::fee_rate_governor::Builder<'a> {
    fn set(&mut self, fee_rate_governor: &FeeRateGovernor) {
        self.set_lamports_per_signature(fee_rate_governor.lamports_per_signature);
        self.set_target_lamports_per_signature(fee_rate_governor.target_lamports_per_signature);
        self.set_target_signatures_per_slot(fee_rate_governor.target_signatures_per_slot);
        self.set_min_lamports_per_signature(fee_rate_governor.min_lamports_per_signature);
        self.set_max_lamports_per_signature(fee_rate_governor.max_lamports_per_signature);
        self.set_burn_percent(fee_rate_governor.burn_percent);
    }
}
impl<'a> snapshot_capnp::fee_rate_governor::Reader<'a> {
    fn get(&self) -> FeeRateGovernor {
        FeeRateGovernor {
            lamports_per_signature: self.get_lamports_per_signature(),
            target_lamports_per_signature: self.get_target_lamports_per_signature(),
            target_signatures_per_slot: self.get_target_signatures_per_slot(),
            min_lamports_per_signature: self.get_min_lamports_per_signature(),
            max_lamports_per_signature: self.get_max_lamports_per_signature(),
            burn_percent: self.get_burn_percent(),
        }
    }
}

impl<'a> snapshot_capnp::rent_collector::Builder<'a> {
    fn set(&mut self, rent_collector: &RentCollector) {
        self.set_epoch(rent_collector.epoch);
        self.set_slots_per_year(rent_collector.slots_per_year);
        self.reborrow().init_rent().set(&rent_collector.rent);
        self.reborrow()
            .init_epoch_schedule()
            .set(&rent_collector.epoch_schedule);
    }
}
impl<'a> snapshot_capnp::rent_collector::Reader<'a> {
    fn get(&self) -> Result<RentCollector> {
        Ok(RentCollector {
            epoch: self.get_epoch(),
            epoch_schedule: self.get_epoch_schedule()?.get(),
            slots_per_year: self.get_slots_per_year(),
            rent: self.get_rent()?.get(),
        })
    }
}

impl<'a> snapshot_capnp::rent::Builder<'a> {
    fn set(&mut self, rent: &Rent) {
        self.set_lamports_per_byte_year(rent.lamports_per_byte_year);
        self.set_exemption_threshold(rent.exemption_threshold);
    }
}
impl<'a> snapshot_capnp::rent::Reader<'a> {
    fn get(&self) -> Rent {
        Rent {
            lamports_per_byte_year: self.get_lamports_per_byte_year(),
            exemption_threshold: self.get_exemption_threshold(),
            burn_percent: self.get_burn_percent(),
        }
    }
}

impl<'a> snapshot_capnp::epoch_schedule::Builder<'a> {
    fn set(&mut self, epoch_schedule: &EpochSchedule) {
        self.set_slots_per_epoch(epoch_schedule.slots_per_epoch);
        self.set_leader_schedule_slot_offset(epoch_schedule.leader_schedule_slot_offset);
        self.set_warmup(epoch_schedule.warmup);
        self.set_first_normal_epoch(epoch_schedule.first_normal_epoch);
        self.set_first_normal_slot(epoch_schedule.first_normal_slot);
    }
}
impl<'a> snapshot_capnp::epoch_schedule::Reader<'a> {
    fn get(&self) -> EpochSchedule {
        EpochSchedule {
            slots_per_epoch: self.get_slots_per_epoch(),
            leader_schedule_slot_offset: self.get_leader_schedule_slot_offset(),
            warmup: self.get_warmup(),
            first_normal_epoch: self.get_first_normal_epoch(),
            first_normal_slot: self.get_first_normal_slot(),
        }
    }
}

impl<'a> snapshot_capnp::inflation::Builder<'a> {
    fn set(&mut self, inflation: &Inflation) {
        self.set_initial(inflation.initial);
        self.set_terminal(inflation.terminal);
        self.set_taper(inflation.taper);
        self.set_foundation(inflation.foundation);
        self.set_foundation_term(inflation.foundation_term);
    }
}
impl<'a> snapshot_capnp::inflation::Reader<'a> {
    fn get(&self) -> Inflation {
        Inflation {
            initial: self.get_initial(),
            terminal: self.get_terminal(),
            taper: self.get_taper(),
            foundation: self.get_foundation(),
            foundation_term: self.get_foundation_term(),
            __unused: f64::default(), // unused
        }
    }
}

impl<'a> snapshot_capnp::stakes::Builder<'a> {
    fn set(&mut self, stakes: &Stakes<Delegation>) {
        self.set_epoch(stakes.epoch);

        {
            let vote_accounts: Arc<VoteAccountsHashMap> = (&stakes.vote_accounts).into();
            let mut vote_accounts_builder = self
                .reborrow()
                .init_vote_accounts(vote_accounts.len().try_into().unwrap());
            for (i, (pubkey, (stake, vote_account))) in vote_accounts.iter().enumerate() {
                let account: AccountSharedData = vote_account.clone().into();
                let mut vote_account_builder = vote_accounts_builder.reborrow().get(i as u32);
                vote_account_builder.reborrow().init_pubkey().set(pubkey);
                vote_account_builder.set_stake(*stake);
                vote_account_builder.init_account().set(account);
            }
        }

        {
            let mut stake_delegations_builder = self
                .reborrow()
                .init_stake_delegations(stakes.stake_delegations.len().try_into().unwrap());
            for (i, (stake_pubkey, delegation)) in stakes.stake_delegations.iter().enumerate() {
                let mut stake_delegation_builder =
                    stake_delegations_builder.reborrow().get(i as u32);
                stake_delegation_builder
                    .reborrow()
                    .init_stake_pubkey()
                    .set(stake_pubkey);
                stake_delegation_builder
                    .reborrow()
                    .init_voter_pubkey()
                    .set(&delegation.voter_pubkey);
                stake_delegation_builder.set_stake(delegation.stake);
                stake_delegation_builder.set_activation_epoch(delegation.activation_epoch);
                stake_delegation_builder.set_deactivation_epoch(delegation.deactivation_epoch);
                stake_delegation_builder.set_warmup_cooldown_rate(delegation.warmup_cooldown_rate);
            }
        }

        {
            let mut stake_history_builder = self
                .reborrow()
                .init_stake_history(stakes.stake_history.len().try_into().unwrap());
            for (i, (epoch, stake_history)) in stakes.stake_history.iter().enumerate() {
                let mut stake_history_entry_builder =
                    stake_history_builder.reborrow().get(i as u32);
                stake_history_entry_builder.set_epoch(*epoch);
                stake_history_entry_builder.set_effective(stake_history.effective);
                stake_history_entry_builder.set_activating(stake_history.activating);
                stake_history_entry_builder.set_deactivating(stake_history.deactivating);
            }
        }
    }
}
impl<'a> snapshot_capnp::stakes::Reader<'a> {
    fn get(&self) -> Result<Stakes<Delegation>> {
        let vote_accounts_reader = self.get_vote_accounts()?;
        let mut vote_accounts =
            VoteAccountsHashMap::with_capacity(vote_accounts_reader.len() as usize);
        for vote_account_reader in vote_accounts_reader.iter() {
            let pubkey = vote_account_reader.get_pubkey()?.get()?;
            let stake = vote_account_reader.get_stake();
            let account: AccountSharedData = vote_account_reader.get_account()?.get()?;
            let old_value = vote_accounts.insert(pubkey, (stake, account.try_into()?));
            assert!(
                old_value.is_none(),
                "key: {pubkey:?}, old value: {old_value:?}"
            )
        }
        let vote_accounts = Arc::new(vote_accounts).into();

        let stake_history_reader = self.get_stake_history()?;
        let mut stake_history = StakeHistory::default();
        for stake_history_entry_reader in stake_history_reader.iter() {
            let epoch = stake_history_entry_reader.get_epoch();
            let stake_history_entry = StakeHistoryEntry {
                effective: stake_history_entry_reader.get_effective(),
                activating: stake_history_entry_reader.get_activating(),
                deactivating: stake_history_entry_reader.get_deactivating(),
            };
            stake_history.add(epoch, stake_history_entry);
        }

        let stake_delegations_reader = self.get_stake_delegations()?;
        let mut stake_delegations = ImHashMap::new();
        for stake_delegation_reader in stake_delegations_reader.iter() {
            let key = stake_delegation_reader.get_stake_pubkey()?.get()?;
            let value = Delegation {
                voter_pubkey: stake_delegation_reader.get_voter_pubkey()?.get()?,
                stake: stake_delegation_reader.get_stake(),
                activation_epoch: stake_delegation_reader.get_activation_epoch(),
                deactivation_epoch: stake_delegation_reader.get_deactivation_epoch(),
                warmup_cooldown_rate: stake_delegation_reader.get_warmup_cooldown_rate(),
            };
            let old_value = stake_delegations.insert(key, value);
            assert!(
                old_value.is_none(),
                "key: {key:?}, old value: {old_value:?}"
            );
        }

        Ok(Stakes::<Delegation> {
            vote_accounts,
            stake_delegations,
            unused: u64::default(),
            epoch: self.get_epoch(),
            stake_history,
        })
    }
}

impl<'a> snapshot_capnp::epoch_stake::Builder<'a> {
    fn set(&mut self, epoch: Epoch, epoch_stake: &EpochStakes) {
        self.set_epoch(epoch);
        self.set_total_stake(epoch_stake.total_stake());
        {
            let stakes = match epoch_stake.stakes() {
                StakesEnum::Accounts(stakes) => stakes.clone().into(),
                StakesEnum::Delegations(stakes) => stakes.clone(),
            };
            self.reborrow().init_stakes().set(&(stakes.into()));
        }

        {
            let mut node_ids_to_vote_accounts_builder =
                self.reborrow().init_node_ids_to_vote_accounts(
                    epoch_stake
                        .node_id_to_vote_accounts()
                        .len()
                        .try_into()
                        .unwrap(),
                );
            for (i, (node_id, node_vote_accounts)) in
                epoch_stake.node_id_to_vote_accounts().iter().enumerate()
            {
                let mut node_id_to_vote_accounts_builder =
                    node_ids_to_vote_accounts_builder.reborrow().get(i as u32);
                node_id_to_vote_accounts_builder
                    .reborrow()
                    .init_node_id()
                    .set(node_id);
                let mut vote_accounts_builder = node_id_to_vote_accounts_builder
                    .reborrow()
                    .init_vote_accounts(node_vote_accounts.vote_accounts.len().try_into().unwrap());
                for (i, vote_account) in node_vote_accounts.vote_accounts.iter().enumerate() {
                    vote_accounts_builder
                        .reborrow()
                        .get(i as u32)
                        .set(vote_account);
                }
            }
        }

        {
            let mut epoch_authorized_voters = self.reborrow().init_epoch_authorized_voters(
                epoch_stake
                    .epoch_authorized_voters()
                    .len()
                    .try_into()
                    .unwrap(),
            );
            for (i, (vote_account, authorized_voter)) in
                epoch_stake.epoch_authorized_voters().iter().enumerate()
            {
                let mut epoch_authorized_voter = epoch_authorized_voters.reborrow().get(i as u32);
                epoch_authorized_voter
                    .reborrow()
                    .init_vote_account()
                    .set(vote_account);
                epoch_authorized_voter
                    .reborrow()
                    .init_authorized_voter()
                    .set(authorized_voter);
            }
        }
    }
}

impl<'a> snapshot_capnp::epoch_rewards::Reader<'a> {
    fn get(&self) -> Result<StartBlockHeightAndRewards> {
        use snapshot_capnp::epoch_rewards::epoch_stake_reward::reward_info::commission::Which;
        let start_block_height = self.get_start_block_height();

        let epoch_stake_rewards_reader = self.get_epoch_stake_rewards()?;
        let mut epoch_stake_rewards =
            Vec::with_capacity(epoch_stake_rewards_reader.len().try_into()?);
        for epoch_stake_reward_reader in epoch_stake_rewards_reader.iter() {
            let stake_pubkey = epoch_stake_reward_reader.get_stake_pubkey()?.get()?;
            let stake_account: AccountSharedData =
                epoch_stake_reward_reader.get_stake_account()?.get()?;
            let stake_reward_info_reader = epoch_stake_reward_reader.get_stake_reward_info()?;
            let stake_reward_info = RewardInfo {
                reward_type: match stake_reward_info_reader.get_reward_kind()? {
                    snapshot_capnp::RewardKind::Fee => RewardType::Fee,
                    snapshot_capnp::RewardKind::Rent => RewardType::Rent,
                    snapshot_capnp::RewardKind::Staking => RewardType::Staking,
                    snapshot_capnp::RewardKind::Voting => RewardType::Voting,
                },
                lamports: stake_reward_info_reader.get_lamports().try_into()?,
                post_balance: stake_reward_info_reader.get_post_balance(),
                commission: match stake_reward_info_reader.get_commission().which()? {
                    Which::None(..) => None,
                    Which::Some(commission) => Some(commission),
                },
            };
            let epoch_stake_reward = StakeReward {
                stake_pubkey,
                stake_reward_info,
                stake_account,
            };
            epoch_stake_rewards.push(epoch_stake_reward);
        }

        Ok(StartBlockHeightAndRewards {
            start_block_height,
            calculated_epoch_stake_rewards: Arc::new(epoch_stake_rewards),
        })
    }
}

impl<'a> snapshot_capnp::incremental_snapshot_persistence::Builder<'a> {
    fn set(&mut self, incremental_snapshot_persistence: &BankIncrementalSnapshotPersistence) {
        self.set_full_slot(incremental_snapshot_persistence.full_slot);
        self.reborrow()
            .init_full_hash()
            .set(&incremental_snapshot_persistence.full_hash.0);
        self.set_full_capitalization(incremental_snapshot_persistence.full_capitalization);
        self.reborrow()
            .init_incremental_hash()
            .set(&incremental_snapshot_persistence.incremental_hash.0);
        self.set_incremental_capitalization(
            incremental_snapshot_persistence.incremental_capitalization,
        );
    }
}
impl<'a> snapshot_capnp::incremental_snapshot_persistence::Reader<'a> {
    fn get(&self) -> Result<BankIncrementalSnapshotPersistence> {
        Ok(BankIncrementalSnapshotPersistence {
            full_slot: self.get_full_slot(),
            full_hash: SerdeAccountsHash(self.get_full_hash()?.get()?),
            full_capitalization: self.get_full_capitalization(),
            incremental_hash: SerdeIncrementalAccountsHash(self.get_incremental_hash()?.get()?),
            incremental_capitalization: self.get_incremental_capitalization(),
        })
    }
}
