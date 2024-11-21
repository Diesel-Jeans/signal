
fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .type_attribute(
            "Envelope",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .type_attribute("DataMessage", "#[derive(bon::Builder)]")
        .type_attribute("Content", "#[derive(bon::Builder)]")
        .type_attribute("Envelope", "#[derive(bon::Builder)]")
        .include_file("_includes.rs")
        .compile_protos(
            &["proto/SignalService.proto", "proto/WebSocketProtocol.proto"],
            &["proto"],
        )?;

    Ok(())
}
