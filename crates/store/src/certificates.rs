//! Certificates issued to USP Agents (US-08/US-18, ADR-080).

use std::collections::HashMap;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::scope::scope_param;
use crate::{DeviceScope, NewUspDevice, Result, Store};

/// Issued cert of a device, public facts only.
/// Cert with device gone or revoked by fingerprint only -> not listed, no such record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentCertificate {
    pub id: Uuid,
    pub device_id: Uuid,
    /// Hex.
    pub serial: String,
    /// SHA-256 of DER cert, hex.
    pub fingerprint: String,
    pub not_after: OffsetDateTime,
    /// true = CSR (key stayed on the Agent); false = generated key.
    pub from_csr: bool,
    pub issued_by: Option<String>,
    pub issued_at: OffsetDateTime,
    pub revoked_at: Option<OffsetDateTime>,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
}

/// Device of a cert bundle request, as in DB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateTarget {
    pub id: Uuid,
    /// `cwmp` or `usp`.
    pub protocol: String,
    pub endpoint_id: Option<String>,
    /// `None` until the device reports it.
    pub oui: Option<String>,
    /// `None` until the device reports it.
    pub serial_number: Option<String>,
    /// `active`, `quarantined` or `retired`.
    pub status: String,
    pub tags: Vec<String>,
}

/// Cert to record, generated key. Public facts only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewCertificate {
    pub device_id: Uuid,
    /// Hex.
    pub serial: String,
    /// SHA-256 of DER cert, hex.
    pub fingerprint: String,
    pub not_after: OffsetDateTime,
}

/// Revoke by fingerprint: what it found + did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintRevocation {
    /// Cert row ID.
    pub id: Uuid,
    /// SHA-256 of DER cert, hex.
    pub fingerprint: String,
    /// Agent it was issued to, if known.
    pub endpoint_id: Option<String>,
    /// `None` -> device deleted, or row made by this revocation.
    pub device_id: Option<Uuid>,
    /// Hex. `None` -> only the fingerprint ever known.
    pub serial: Option<String>,
    /// `None` = unknown -> never treated as expired.
    pub not_after: Option<OffsetDateTime>,
    /// First revocation time if revoked before.
    pub revoked_at: OffsetDateTime,
    pub revoked_by: Option<String>,
    pub revoke_reason: Option<String>,
    /// true = DB had a row for this fingerprint; false = row made now.
    pub known: bool,
}

impl Store {
    /// Devices of `tenant_id` by ID or USP EndpointID, max 1 row per device.
    /// Any protocol or status. Name with no match -> no row.
    pub async fn certificate_targets(
        &self,
        tenant_id: Uuid,
        ids: &[Uuid],
        endpoint_ids: &[String],
    ) -> Result<Vec<CertificateTarget>> {
        Ok(sqlx::query_as!(
            CertificateTarget,
            r#"
            SELECT id, protocol, endpoint_id, oui, serial_number, status, tags
            FROM devices
            WHERE tenant_id = $1
              AND (id = ANY($2) OR (protocol = 'usp' AND endpoint_id = ANY($3)))
            "#,
            tenant_id,
            ids,
            endpoint_ids
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Record certs with generated keys. All or none.
    pub async fn record_certificates(
        &self,
        tenant_id: Uuid,
        issued_by: Option<&str>,
        certs: &[NewCertificate],
    ) -> Result<()> {
        self.record_certificates_creating(tenant_id, issued_by, &[], certs)
            .await
    }

    /// Register Agents of `new_devices` not known yet, then record certs with generated keys.
    /// One transaction -> all or none.
    /// Cert -> new Agent by the ID in [`NewUspDevice`].
    /// EndpointID registered meanwhile -> cert goes to the registered device.
    pub async fn record_certificates_creating(
        &self,
        tenant_id: Uuid,
        issued_by: Option<&str>,
        new_devices: &[NewUspDevice],
        certs: &[NewCertificate],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let mut actual: HashMap<Uuid, Uuid> = HashMap::new();
        if !new_devices.is_empty() {
            let wanted: Vec<Uuid> = new_devices.iter().map(|d| d.id).collect();
            let endpoint_ids: Vec<String> =
                new_devices.iter().map(|d| d.endpoint_id.clone()).collect();
            let mut tag_owners = Vec::new();
            let mut tags = Vec::new();
            for d in new_devices {
                for t in &d.tags {
                    tag_owners.push(d.id);
                    tags.push(t.clone());
                }
            }
            sqlx::query!(
                r#"
                INSERT INTO devices (id, tenant_id, protocol, endpoint_id, tags)
                SELECT w.id, $1, 'usp', w.endpoint_id,
                       COALESCE((SELECT array_agg(t.tag ORDER BY t.n)
                                 FROM unnest($4::uuid[], $5::text[])
                                      WITH ORDINALITY AS t(device_id, tag, n)
                                 WHERE t.device_id = w.id), '{}')
                FROM unnest($2::uuid[], $3::text[]) AS w(id, endpoint_id)
                ON CONFLICT (tenant_id, endpoint_id) WHERE protocol = 'usp' DO NOTHING
                "#,
                tenant_id,
                &wanted,
                &endpoint_ids,
                &tag_owners,
                &tags
            )
            .execute(&mut *tx)
            .await?;
            // Wanted ID -> actual device: itself, or the one registered first.
            let rows = sqlx::query!(
                r#"
                SELECT w.id AS "wanted!", d.id AS "actual!"
                FROM unnest($2::uuid[], $3::text[]) AS w(id, endpoint_id)
                JOIN devices d ON d.tenant_id = $1 AND d.protocol = 'usp'
                              AND d.endpoint_id = w.endpoint_id
                "#,
                tenant_id,
                &wanted,
                &endpoint_ids
            )
            .fetch_all(&mut *tx)
            .await?;
            actual = rows.into_iter().map(|r| (r.wanted, r.actual)).collect();
        }
        let ids: Vec<Uuid> = certs.iter().map(|_| Uuid::now_v7()).collect();
        let devices: Vec<Uuid> = certs
            .iter()
            .map(|c| actual.get(&c.device_id).copied().unwrap_or(c.device_id))
            .collect();
        let serials: Vec<String> = certs.iter().map(|c| c.serial.clone()).collect();
        let fingerprints: Vec<String> = certs.iter().map(|c| c.fingerprint.clone()).collect();
        let expiries: Vec<OffsetDateTime> = certs.iter().map(|c| c.not_after).collect();
        sqlx::query!(
            r#"
            INSERT INTO usp_certificates (id, tenant_id, device_id, endpoint_id, serial, fingerprint,
                                          not_after, from_csr, issued_by)
            SELECT u.id, $1, u.device_id,
                   (SELECT d.endpoint_id FROM devices d WHERE d.id = u.device_id AND d.protocol = 'usp'),
                   u.serial, u.fingerprint, u.not_after, false, $2
            FROM unnest($3::uuid[], $4::uuid[], $5::text[], $6::text[], $7::timestamptz[])
                 AS u(id, device_id, serial, fingerprint, not_after)
            "#,
            tenant_id,
            issued_by,
            &ids,
            &devices,
            &serials,
            &fingerprints,
            &expiries
        )
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Record one issued cert (CSR or generated key).
    #[allow(clippy::too_many_arguments)]
    pub async fn record_certificate(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        serial: &str,
        fingerprint: &str,
        not_after: OffsetDateTime,
        from_csr: bool,
        issued_by: Option<&str>,
    ) -> Result<Uuid> {
        let id = Uuid::now_v7();
        sqlx::query!(
            r#"
            INSERT INTO usp_certificates (id, tenant_id, device_id, endpoint_id, serial, fingerprint,
                                          not_after, from_csr, issued_by)
            VALUES ($1, $2, $3,
                    (SELECT d.endpoint_id FROM devices d WHERE d.id = $3 AND d.protocol = 'usp'),
                    $4, $5, $6, $7, $8)
            "#,
            id,
            tenant_id,
            device_id,
            serial,
            fingerprint,
            not_after,
            from_csr,
            issued_by
        )
        .execute(&self.pool)
        .await?;
        Ok(id)
    }

    /// Certs of a device, newest first.
    pub async fn device_certificates(&self, device_id: Uuid) -> Result<Vec<AgentCertificate>> {
        Ok(sqlx::query_as!(
            AgentCertificate,
            r#"
            SELECT id, device_id AS "device_id!", serial AS "serial!", fingerprint,
                   not_after AS "not_after!", from_csr, issued_by, issued_at,
                   revoked_at, revoked_by, revoke_reason
            FROM usp_certificates WHERE device_id = $1 ORDER BY issued_at DESC
            "#,
            device_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Revoke a cert of a device -> the cert, `None` if unknown.
    /// Revoke x2 -> first revocation kept.
    pub async fn revoke_certificate(
        &self,
        device_id: Uuid,
        id: Uuid,
        by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<Option<AgentCertificate>> {
        Ok(sqlx::query_as!(
            AgentCertificate,
            r#"
            UPDATE usp_certificates
            SET revoked_at = COALESCE(revoked_at, now()),
                revoked_by = CASE WHEN revoked_at IS NULL THEN $3 ELSE revoked_by END,
                revoke_reason = CASE WHEN revoked_at IS NULL THEN $4 ELSE revoke_reason END
            WHERE id = $2 AND device_id = $1
            RETURNING id, device_id AS "device_id!", serial AS "serial!", fingerprint,
                      not_after AS "not_after!", from_csr, issued_by, issued_at, revoked_at,
                      revoked_by, revoke_reason
            "#,
            device_id,
            id,
            by,
            reason
        )
        .fetch_optional(&self.pool)
        .await?)
    }

    /// Revoke the cert with this SHA-256 fingerprint (lowercase hex), known or not.
    /// Use: cert record lost, or device deleted without revoke.
    /// Known cert -> revoked (first revocation stays).
    /// Unknown -> new revoked row, no device/serial/expiry -> MTPs refuse the fingerprint.
    /// `endpoint_id` kept when the row has none.
    pub async fn revoke_fingerprint(
        &self,
        tenant_id: Uuid,
        fingerprint: &str,
        endpoint_id: Option<&str>,
        by: Option<&str>,
        reason: Option<&str>,
    ) -> Result<FingerprintRevocation> {
        let mut tx = self.pool.begin().await?;
        // Unrecorded cert -> one row, revoked from the start.
        // 2 requests race -> unique index on fingerprint decides.
        let recorded = sqlx::query_as!(
            FingerprintRevocation,
            r#"
            INSERT INTO usp_certificates (id, tenant_id, endpoint_id, fingerprint, from_csr,
                                          revoked_at, revoked_by, revoke_reason)
            VALUES ($1, $2, $3, $4, false, now(), $5, $6)
            ON CONFLICT (tenant_id, fingerprint) DO NOTHING
            RETURNING id, fingerprint, endpoint_id, device_id, serial, not_after,
                      revoked_at AS "revoked_at!", revoked_by, revoke_reason,
                      false AS "known!"
            "#,
            Uuid::now_v7(),
            tenant_id,
            endpoint_id,
            fingerprint,
            by,
            reason
        )
        .fetch_optional(&mut *tx)
        .await?;
        let done = match recorded {
            Some(r) => r,
            None => {
                sqlx::query_as!(
                    FingerprintRevocation,
                    r#"
                    UPDATE usp_certificates
                    SET revoked_at = COALESCE(revoked_at, now()),
                        revoked_by = CASE WHEN revoked_at IS NULL THEN $3 ELSE revoked_by END,
                        revoke_reason = CASE WHEN revoked_at IS NULL THEN $4 ELSE revoke_reason END,
                        endpoint_id = COALESCE(endpoint_id, $5)
                    WHERE tenant_id = $1 AND fingerprint = $2
                    RETURNING id, fingerprint, endpoint_id, device_id, serial, not_after,
                              revoked_at AS "revoked_at!", revoked_by, revoke_reason,
                              true AS "known!"
                    "#,
                    tenant_id,
                    fingerprint,
                    by,
                    reason,
                    endpoint_id
                )
                .fetch_one(&mut *tx)
                .await?
            }
        };
        tx.commit().await?;
        Ok(done)
    }

    /// Fingerprints of revoked, unexpired certs, device still there or not.
    /// Expired -> TLS handshake fails anyway.
    /// Revoked by fingerprint only -> no known expiry -> stays in the set.
    pub async fn revoked_fingerprints(&self, tenant_id: Uuid) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT fingerprint FROM usp_certificates
            WHERE tenant_id = $1 AND revoked_at IS NOT NULL
              AND (not_after IS NULL OR not_after > now())
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// EndpointIDs of USP Agents with an issued, unrevoked cert.
    /// Such Agent must prove itself with it on every MTP -> no way in with a shared account.
    /// Expiry does not free the EndpointID.
    /// Expired cert, not replaced or revoked = device to fix, not free for a claim.
    /// EndpointID recorded with the cert -> no need of the device row
    /// (device delete revokes its certs first).
    pub async fn certificate_bound_endpoints(&self, tenant_id: Uuid) -> Result<Vec<String>> {
        Ok(sqlx::query_scalar!(
            r#"
            SELECT DISTINCT endpoint_id AS "endpoint_id!"
            FROM usp_certificates
            WHERE tenant_id = $1 AND revoked_at IS NULL AND endpoint_id IS NOT NULL
            "#,
            tenant_id
        )
        .fetch_all(&self.pool)
        .await?)
    }

    /// Live (unrevoked, unexpired) certs expiring within `days`, devices in `scope`.
    /// Soonest first.
    pub async fn expiring_certificates(
        &self,
        tenant_id: Uuid,
        days: i32,
        scope: Option<&DeviceScope>,
        limit: i64,
    ) -> Result<Vec<AgentCertificate>> {
        Ok(sqlx::query_as!(
            AgentCertificate,
            r#"
            SELECT c.id, c.device_id AS "device_id!", c.serial AS "serial!", c.fingerprint,
                   c.not_after AS "not_after!", c.from_csr, c.issued_by, c.issued_at,
                   c.revoked_at, c.revoked_by, c.revoke_reason
            FROM usp_certificates c JOIN devices d ON d.id = c.device_id
            WHERE c.tenant_id = $1 AND c.revoked_at IS NULL AND c.not_after > now()
              AND c.not_after < now() + make_interval(days => $2)
              AND device_in_scope(d, $3)
              -- A newer live certificate of the same device replaces it.
              AND NOT EXISTS (
                  SELECT 1 FROM usp_certificates n
                  WHERE n.device_id = c.device_id AND n.revoked_at IS NULL
                    AND n.not_after > c.not_after)
            ORDER BY c.not_after LIMIT $4
            "#,
            tenant_id,
            days,
            scope_param(scope),
            limit
        )
        .fetch_all(&self.pool)
        .await?)
    }
}
