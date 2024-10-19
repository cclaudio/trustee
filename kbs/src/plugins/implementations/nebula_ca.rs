// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::tempdir_in;

use crate::plugins::plugin_manager::ClientPlugin;

/// Parameters for the credential request
///
/// These parameters are provided in the request via URL query string. They match
/// the "./nebula-cert sign <...>" parameters.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct NebulaCredentialParams {
    /// Required: name of the cert, usually hostname or podname
    name: String,
    /// Required: IPv4 address and network in CIDR notation to assign the cert
    ip: String,
    /// Optional: how long the cert should be valid for.
    /// The default is 1 second before the signing cert expires.
    /// Valid time units are seconds: "s", minutes: "m", hours: "h".
    duration: Option<String>,
    /// Optional: comma separated list of groups.
    groups: Option<String>,
    /// Optional: comma separated list of ipv4 address and network in CIDR notation.
    /// Subnets this cert can serve for
    subnets: Option<String>,
}

impl TryFrom<&str> for NebulaCredentialParams {
    type Error = Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: NebulaCredentialParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}

impl From<&NebulaCredentialParams> for Vec<OsString> {
    fn from(params: &NebulaCredentialParams) -> Self {
        let mut args: Vec<OsString> = vec![
            "-name".into(),
            params.name.as_str().into(),
            "-ip".into(),
            params.ip.as_str().into(),
        ];

        if let Some(value) = &params.duration {
            args.extend_from_slice(&["-duration".into(), value.into()]);
        }
        if let Some(value) = &params.groups {
            args.extend_from_slice(&["-groups".into(), value.into()]);
        }
        if let Some(value) = &params.subnets {
            args.extend_from_slice(&["-subnets".into(), value.into()]);
        }

        args
    }
}

#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
pub struct NebulaCaConfig {
    nebula_cert_bin_path: String,
    work_dir: String,
    self_signed_ca: SelfSignedNebulaCa,
}

impl TryFrom<NebulaCaConfig> for NebulaCa {
    type Error = Error;

    fn try_from(config: NebulaCaConfig) -> Result<Self> {
        let work_dir = PathBuf::from(config.work_dir.as_str());
        let crt = work_dir.join("ca/ca.crt");
        let key = work_dir.join("ca/ca.key");
        let nebula = NebulaCertBin {
            path: PathBuf::from(config.nebula_cert_bin_path.as_str()),
        };

        // Print version and ensure the binary is working.
        log::info!("nebula-cert binary: {}", nebula.version()?.trim());

        if let Some(parent) = crt.as_path().parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Create {} dir", parent.display()))?;
        }

        // Create self-signed certificate authority
        if !crt.exists() && !key.exists() {
            let mut args: Vec<OsString> = Vec::from(&config.self_signed_ca);
            args.extend_from_slice(&[
                "-out-crt".into(),
                crt.as_path().into(),
                "-out-key".into(),
                key.as_path().into(),
            ]);
            nebula.ca(&args)?;
            log::info!("Nebula CA credential created");
        } else {
            log::warn!("Reusing existing Nebula CA credentials");
        }

        if !crt.exists() || !key.exists() {
            bail!("Nebula CA can't be (re)used: certificate/key is missing");
        }

        Ok(NebulaCa {
            nebula,
            crt,
            key,
            work_dir,
        })
    }
}

/// "nebula-cert" binary parameters to create a self signed certificate authority
/// Documentation: https://github.com/slackhq/nebula or "./nebula-cert ca --help"
#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
struct SelfSignedNebulaCa {
    name: String,
    argon_iterations: Option<u32>,
    argon_memory: Option<u32>,
    argon_parallelism: Option<u32>,
    curve: Option<String>,
    duration: Option<String>,
    groups: Option<String>,
    ips: Option<String>,
    out_qr: Option<String>,
    subnets: Option<String>,
}

impl From<&SelfSignedNebulaCa> for Vec<OsString> {
    fn from(ca: &SelfSignedNebulaCa) -> Self {
        let mut args: Vec<OsString> = vec!["-name".into(), ca.name.as_str().into()];
        if let Some(value) = &ca.argon_iterations {
            args.extend_from_slice(&["-argon-iterations".into(), value.to_string().into()]);
        }
        if let Some(value) = &ca.argon_memory {
            args.extend_from_slice(&["-argon-memory".into(), value.to_string().into()]);
        }
        if let Some(value) = &ca.argon_parallelism {
            args.extend_from_slice(&["-argon-parallelism".into(), value.to_string().into()]);
        }
        if let Some(value) = &ca.curve {
            args.extend_from_slice(&["-curve".into(), value.into()]);
        }
        if let Some(value) = &ca.duration {
            args.extend_from_slice(&["-duration".into(), value.into()]);
        }
        if let Some(value) = &ca.groups {
            args.extend_from_slice(&["-groups".into(), value.into()]);
        }
        if let Some(value) = &ca.ips {
            args.extend_from_slice(&["-ips".into(), value.into()]);
        }
        if let Some(value) = &ca.out_qr {
            args.extend_from_slice(&["-out-qr".into(), value.into()]);
        }
        if let Some(value) = &ca.subnets {
            args.extend_from_slice(&["-subnets".into(), value.into()]);
        }

        args
    }
}

#[derive(Debug)]
struct NebulaCertBin {
    path: PathBuf,
}

impl NebulaCertBin {
    /// Create and sign a certificate
    pub async fn sign(&self, args: &Vec<OsString>) -> Result<()> {
        let mut cmd = tokio::process::Command::new(self.path.as_path());
        cmd.arg("sign").args(args);
        let status =
            cmd.status()
                .await
                .context(format!("{} sign {:?}", self.path.display(), args))?;
        if !status.success() {
            return Err(anyhow!("{} sign {:?}", self.path.display(), args));
        }
        Ok(())
    }

    /// Create a self signed certificate authority
    pub fn ca(&self, args: &Vec<OsString>) -> Result<()> {
        let mut cmd = Command::new(self.path.as_path());
        cmd.arg("ca").args(args);
        let status = cmd
            .status()
            .context(format!("{} ca {:?}", self.path.display(), args))?;
        if !status.success() {
            return Err(anyhow!("{} ca {:?}", self.path.display(), args));
        }
        Ok(())
    }

    /// Verify if a certificate isn't expired and was signed by a trusted authority.
    pub fn verify(&self, args: &Vec<OsString>) -> Result<()> {
        let mut cmd = Command::new(self.path.as_path());
        cmd.arg("verify").args(args);
        let status = cmd
            .status()
            .context(format!("{} verify {:?}", self.path.display(), args))?;
        if !status.success() {
            return Err(anyhow!("{} verify {:?}", self.path.display(), args));
        }
        Ok(())
    }

    /// Print the nebula-cert binary version
    pub fn version(&self) -> Result<String> {
        let output = Command::new(self.path.as_path())
            .arg("--version")
            .output()
            .context(format!("'{} --version' failed to run", self.path.display()))?;

        if !output.status.success() {
            return Err(anyhow!(
                "'{} --version' failed to complete",
                self.path.display()
            ));
        }

        Ok(String::from_utf8(output.stdout)?)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct Credential {
    pub node_crt: Vec<u8>,
    pub node_key: Vec<u8>,
    pub ca_crt: Vec<u8>,
}

/// Nebula Certificate Authority
#[derive(Debug)]
pub struct NebulaCa {
    nebula: NebulaCertBin,
    key: PathBuf,
    crt: PathBuf,
    work_dir: PathBuf,
}

impl NebulaCa {
    pub async fn create_credential(
        &self,
        node_key: &Path,
        node_crt: &Path,
        params: &NebulaCredentialParams,
    ) -> Result<Credential> {
        let mut args: Vec<OsString> = Vec::from(params);
        args.extend_from_slice(&[
            "-ca-key".into(),
            self.key.as_path().into(),
            "-ca-crt".into(),
            self.crt.as_path().into(),
            "-out-key".into(),
            node_key.into(),
            "-out-crt".into(),
            node_crt.into(),
        ]);

        self.nebula
            .sign(&args)
            .await
            .context("Failed to create credential")?;

        let credential = Credential {
            node_crt: tokio::fs::read(node_crt)
                .await
                .context(format!("read {}", node_crt.display()))?,
            node_key: tokio::fs::read(node_key)
                .await
                .context(format!("read {}", node_key.display()))?,
            ca_crt: tokio::fs::read(self.crt.as_path())
                .await
                .context(format!("read {}", self.crt.display()))?,
        };

        Ok(credential)
    }

    pub fn verify_credential(&self, node_crt: &Path) -> Result<()> {
        let args: Vec<OsString> = vec![
            "-ca".into(),
            self.crt.as_path().into(),
            "-crt".into(),
            node_crt.into(),
        ];
        self.nebula
            .verify(&args)
            .context("Failed to verify credential")?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl ClientPlugin for NebulaCa {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        // The Nebula CA plugin is stateless, so none of request types below should
        // store state.
        match sub_path {
            // Create credential for the provided parameters.
            // The credential directory (and its files) is auto-deleted after the Credential is returned.
            "credential" => {
                let params = NebulaCredentialParams::try_from(query)?;

                let credential_dir = tempdir_in(self.work_dir.as_path())?;
                let node_key: PathBuf = credential_dir.path().to_owned().join("node.key");
                let node_crt: PathBuf = credential_dir.path().to_owned().join("node.crt");

                let credential = self
                    .create_credential(node_key.as_path(), node_crt.as_path(), &params)
                    .await?;

                Ok(serde_json::to_vec(&credential)?)
            }
            _ => Err(anyhow!("{} not supported", sub_path))?,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::ffi::OsString;

    use super::NebulaCredentialParams;

    #[rstest]
    #[case(
        "name=pod1&ip=1.2.3.4/21",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into()
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4".into()
        ])
    )]
    #[case(
        "name=pod1&ip=1.2",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2".into()
        ])
    )]
    #[case("name=pod1", None)]
    #[case(
        "name=pod1&ip=1.2.3.4/21&duration=8760h10m10s",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-duration".into(),
            "8760h10m10s".into(),
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4/21&groups=server,ssh",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-groups".into(),
            "server,ssh".into(),
        ])
    )]
    #[case(
        "name=pod1&ip=1.2.3.4/21&subnets=1.2.3.5/21,1.2.3.6/21",
        Some(vec![
            "-name".into(),
            "pod1".into(),
            "-ip".into(),
            "1.2.3.4/21".into(),
            "-subnets".into(),
            "1.2.3.5/21,1.2.3.6/21".into(),
        ])
    )]
    fn test_generate_cmd_sign_args(#[case] query: &str, #[case] expected: Option<Vec<OsString>>) {
        let credential_params = NebulaCredentialParams::try_from(query);
        if expected.is_none() {
            assert!(credential_params.is_err())
        } else {
            let cmd_args: Vec<OsString> = Vec::from(&credential_params.unwrap());
            assert_eq!(cmd_args, expected.unwrap())
        }
    }
}
