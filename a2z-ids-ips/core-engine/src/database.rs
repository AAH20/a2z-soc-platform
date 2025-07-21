use anyhow::Result;
use sqlx::{PgPool, Row};
use serde_json::Value;
use std::env;
use tracing::{info, error, warn};
use uuid::Uuid;

pub struct DatabaseConnection {
    pool: PgPool,
}

impl DatabaseConnection {
    pub async fn new() -> Result<Self> {
        let database_url = env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgresql://postgres:postgres@localhost:5432/a2z_soc".to_string());

        let pool = PgPool::connect(&database_url).await?;
        
        info!("✅ IDS/IPS Database connection established");
        
        Ok(Self { pool })
    }

    pub async fn store_detection_event(&self, event: &DetectionEvent) -> Result<i64> {
        let query = r#"
            INSERT INTO ids_logs (
                agent_id, event_type, severity, source_ip, destination_ip,
                source_port, destination_port, protocol, signature_id,
                rule_name, message, packet_data, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
            RETURNING id
        "#;

        let row = sqlx::query(query)
            .bind(&event.agent_id)
            .bind(&event.event_type)
            .bind(&event.severity)
            .bind(&event.source_ip)
            .bind(&event.destination_ip)
            .bind(event.source_port)
            .bind(event.destination_port)
            .bind(&event.protocol)
            .bind(&event.signature_id)
            .bind(&event.rule_name)
            .bind(&event.message)
            .bind(&event.packet_data)
            .bind(&event.created_at)
            .bind(&event.updated_at)
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get("id"))
    }

    pub async fn store_security_event(&self, event: &SecurityEvent) -> Result<i64> {
        let query = r#"
            INSERT INTO security_events (
                agent_id, event_type, severity, title, description,
                source_ip, destination_ip, indicators, raw_data,
                created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING id
        "#;

        let row = sqlx::query(query)
            .bind(&event.agent_id)
            .bind(&event.event_type)
            .bind(&event.severity)
            .bind(&event.title)
            .bind(&event.description)
            .bind(&event.source_ip)
            .bind(&event.destination_ip)
            .bind(&event.indicators)
            .bind(&event.raw_data)
            .bind(&event.created_at)
            .bind(&event.updated_at)
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get("id"))
    }

    pub async fn update_agent_status(&self, agent_id: &str, status: &str) -> Result<()> {
        let query = r#"
            INSERT INTO agent_configurations (
                agent_id, agent_type, status, last_heartbeat, updated_at
            ) VALUES ($1, 'ids-ips', $2, NOW(), NOW())
            ON CONFLICT (agent_id) DO UPDATE SET
                status = EXCLUDED.status,
                last_heartbeat = EXCLUDED.last_heartbeat,
                updated_at = EXCLUDED.updated_at
        "#;

        sqlx::query(query)
            .bind(agent_id)
            .bind(status)
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    pub async fn get_detection_rules(&self) -> Result<Vec<DetectionRule>> {
        let query = r#"
            SELECT id, name, pattern, severity, enabled, created_at
            FROM detection_rules
            WHERE enabled = true
            ORDER BY severity DESC, created_at DESC
        "#;

        let rows = sqlx::query(query)
            .fetch_all(&self.pool)
            .await?;

        let mut rules = Vec::new();
        for row in rows {
            rules.push(DetectionRule {
                id: row.get("id"),
                name: row.get("name"),
                pattern: row.get("pattern"),
                severity: row.get("severity"),
                enabled: row.get("enabled"),
                created_at: row.get("created_at"),
            });
        }

        Ok(rules)
    }

    pub async fn create_detection_rule(&self, rule: &DetectionRule) -> Result<i64> {
        let query = r#"
            INSERT INTO detection_rules (
                name, pattern, severity, enabled, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, NOW(), NOW())
            RETURNING id
        "#;

        let row = sqlx::query(query)
            .bind(&rule.name)
            .bind(&rule.pattern)
            .bind(&rule.severity)
            .bind(rule.enabled)
            .fetch_one(&self.pool)
            .await?;

        Ok(row.get("id"))
    }

    pub async fn get_recent_events(&self, limit: i64) -> Result<Vec<DetectionEvent>> {
        let query = r#"
            SELECT 
                agent_id, event_type, severity, source_ip, destination_ip,
                source_port, destination_port, protocol, signature_id,
                rule_name, message, packet_data, created_at, updated_at
            FROM ids_logs
            ORDER BY created_at DESC
            LIMIT $1
        "#;

        let rows = sqlx::query(query)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?;

        let mut events = Vec::new();
        for row in rows {
            events.push(DetectionEvent {
                agent_id: row.get("agent_id"),
                event_type: row.get("event_type"),
                severity: row.get("severity"),
                source_ip: row.get("source_ip"),
                destination_ip: row.get("destination_ip"),
                source_port: row.get("source_port"),
                destination_port: row.get("destination_port"),
                protocol: row.get("protocol"),
                signature_id: row.get("signature_id"),
                rule_name: row.get("rule_name"),
                message: row.get("message"),
                packet_data: row.get("packet_data"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            });
        }

        Ok(events)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub agent_id: String,
    pub event_type: String,
    pub severity: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<i32>,
    pub destination_port: Option<i32>,
    pub protocol: Option<String>,
    pub signature_id: Option<String>,
    pub rule_name: Option<String>,
    pub message: String,
    pub packet_data: Option<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct SecurityEvent {
    pub agent_id: String,
    pub event_type: String,
    pub severity: String,
    pub title: String,
    pub description: String,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub indicators: Option<Value>,
    pub raw_data: Option<Value>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone)]
pub struct DetectionRule {
    pub id: Option<i64>,
    pub name: String,
    pub pattern: String,
    pub severity: String,
    pub enabled: bool,
    pub created_at: Option<chrono::DateTime<chrono::Utc>>,
} 