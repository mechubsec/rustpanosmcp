//! Verify audit events are emitted for tool calls.

use rust_panosmcp_core::{
    inventory::Inventory,
    tools::{ExecutePanosOpInput, GatherDeviceFactsInput, PanosService},
};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[tokio::test]
#[ignore = "requires PANOS_LAB_INVENTORY, PANOS_LAB_DEVICE, network access, and its referenced API-key secret"]
async fn audit_events_emitted_for_tool_calls() {
    // Initialize tracing to capture audit events
    let audit_cfg = rust_panosmcp_core::observability::AuditConfig {
        format: rust_panosmcp_core::observability::AuditFormat::Text,
        audit_log_file: None,
        redaction: None,
        journald: false,
        otel: None,
    };
    let _ = rust_panosmcp_core::observability::init_tracing(&audit_cfg);

    let inventory_path = std::env::var_os("PANOS_LAB_INVENTORY")
        .map(PathBuf::from)
        .expect("PANOS_LAB_INVENTORY must name an absolute inventory path");
    let device = std::env::var("PANOS_LAB_DEVICE")
        .expect("PANOS_LAB_DEVICE must name one exact inventory entry");
    let service = PanosService::new(Inventory::load(inventory_path).expect("lab inventory"))
        .expect("lab PAN-OS service");

    // Call gather_device_facts - should emit audit event
    service
        .gather_device_facts(
            GatherDeviceFactsInput {
                device: device.clone(),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("gather_device_facts");

    // Call execute_panos_op - should emit audit event
    service
        .execute_panos_op(
            ExecutePanosOpInput {
                device,
                command: "<show><system><info/></system></show>".to_owned(),
                max_bytes: Some(256 * 1024),
                max_lines: Some(5_000),
            },
            None,
            CancellationToken::new(),
        )
        .await
        .expect("execute_panos_op");

    // In a real test we'd capture the log output and verify audit events were emitted
    // For now, this just ensures the code paths work without panicking
}
