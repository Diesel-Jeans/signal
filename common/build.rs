fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .type_attribute(
            "Envelope",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(&["signal.proto"], &["proto"])?;
    Ok(())
}
