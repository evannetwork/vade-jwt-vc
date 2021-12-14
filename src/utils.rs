/*
  Copyright (c) 2018-present evan GmbH.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

use base64::Config;
#[cfg(not(target_arch = "wasm32"))]
use chrono::Utc;
use std::error::Error;

pub fn get_now_as_iso_string() -> String {
    #[cfg(target_arch = "wasm32")]
    return js_sys::Date::new_0().to_iso_string().to_string().into();
    #[cfg(not(target_arch = "wasm32"))]
    return Utc::now().format("%Y-%m-%dT%H:%M:%S.000Z").to_string();
}

pub fn decode_base64<T: AsRef<[u8]>>(
    encoded: T,
    error_message_context: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode(encoded).map_err(|_| {
        format!(
            "Error interpreting {} as base64. Wrong encoding?",
            error_message_context
        )
    })?;

    Ok(decoded)
}

pub fn decode_base64_config<T: AsRef<[u8]>>(
    encoded: T,
    config: Config,
    error_message_context: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let decoded = base64::decode_config(encoded, config).map_err(|_| {
        format!(
            "Error interpreting {} as base64. Wrong encoding?",
            error_message_context
        )
    })?;

    Ok(decoded)
}
