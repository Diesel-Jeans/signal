fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .type_attribute(
            "Envelope",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .include_file("_includes.rs")
        .compile_protos(
            &["proto/SignalService.proto", "proto/WebSocketProtocol.proto"],
            &["proto"],
        )?;

    Ok(())
}
