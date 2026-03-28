fn main() {
    prost_build::Config::new()
        .compile_protos(
            &[
                "proto/transportinstruction.proto",
                "proto/hostinput.proto",
                "proto/userinput.proto",
            ],
            &["proto/"],
        )
        .expect("Failed to compile protobuf definitions");
}
