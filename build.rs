fn main() {
    println!("cargo:rerun-if-changed=schema");
    capnpc::CompilerCommand::new()
        .file("schema/snapshot.capnp")
        .run()
        .expect("compiling schema");
}
