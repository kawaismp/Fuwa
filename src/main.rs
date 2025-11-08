use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, post, web};
use dotenvy::dotenv;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::env;
use std::time::Duration;
use thiserror::Error;

#[derive(Deserialize)]
struct Interaction {
    #[serde(rename = "type")]
    interaction_type: u8,
    data: Option<InteractionData>,
    member: Option<Member>,
    user: Option<User>,
}

#[derive(Deserialize)]
struct InteractionData {
    name: String,
    options: Option<Vec<CommandOption>>,
}

#[derive(Deserialize)]
struct CommandOption {
    name: String,
    value: serde_json::Value,
}

#[derive(Deserialize)]
struct Member {
    user: User,
}

#[derive(Deserialize)]
struct User {
    id: String,
}

#[derive(Deserialize)]
struct MinecraftLinkResponse {
    success: bool,
    minecraft_username: Option<String>,
    message: Option<String>,
}

#[derive(Error, Debug)]
enum InteractionError {
    #[error("Missing or invalid headers: {0}")]
    Header(String),
    #[error("Invalid signature: {0}")]
    Signature(String),
    #[error("Invalid JSON body: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Server config error: {0}")]
    Config(String),
    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),
    #[error("Verification failed: {0}")]
    Verification(String),
    #[error("Internal error: {0}")]
    Internal(String),
}

fn error_response(error: &InteractionError) -> HttpResponse {
    tracing::error!(target: "interaction", "{}", error);
    let (title, description, color) = match error {
        InteractionError::Header(_) => (
            "<:no:826338754650046464> Unauthorized",
            "Missing or invalid request headers.",
            0xFF0000,
        ),
        InteractionError::Signature(_) => (
            "<:no:826338754650046464> Invalid Request",
            "The request signature could not be verified.",
            0xFF0000,
        ),
        InteractionError::Config(_) => (
            "<:no:826338754650046464> Server Configuration Error",
            "Server is not properly configured. Please contact an admin.",
            0xFF0000,
        ),
        InteractionError::Network(_) => (
            "<:no:826338754650046464> Connection Error",
            "Could not reach Minecraft server. Please try again later.",
            0xFF0000,
        ),
        InteractionError::Verification(msg) => (
            "<:no:826338754650046464> Verification Failed",
            msg.as_str(),
            0xFF0000,
        ),
        _ => (
            "<:no:826338754650046464> Internal Error",
            "An unexpected error occurred.",
            0xFF0000,
        ),
    };

    let response = serde_json::json!({
        "type": 4,
        "data": {
            "embeds": [{
                "title": title,
                "description": description,
                "color": color
            }],
            "flags": 64
        }
    });
    HttpResponse::Ok().json(response)
}

#[post("/interactions")]
async fn interactions(req: HttpRequest, body: web::Bytes) -> impl Responder {
    match handle_interaction(req, body).await {
        Ok(resp) => resp,
        Err(e) => error_response(&e),
    }
}

async fn handle_interaction(req: HttpRequest, body: web::Bytes) -> Result<HttpResponse, InteractionError> {
    // Step 1: Verify Discord signature
    let signature = req
        .headers()
        .get("x-signature-ed25519")
        .and_then(|v| v.to_str().ok());
    let timestamp = req
        .headers()
        .get("x-signature-timestamp")
        .and_then(|v| v.to_str().ok());

    if signature.is_none() || timestamp.is_none() {
        return Err(InteractionError::Header("Missing signature or timestamp".into()));
    }

    let signature_str = signature.unwrap();
    let timestamp_str = timestamp.unwrap();

    // Validate timestamp to prevent replay attacks (Discord recommends 5 minute window)
    if let Ok(timestamp_value) = timestamp_str.parse::<i64>() {
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs() as i64;

        let time_diff = (current_time - timestamp_value).abs();
        if time_diff > 300 {
            // 5 minutes = 300 seconds
            return Err(InteractionError::Header("Request timestamp too old or invalid".into()));
        }
    } else {
        return Err(InteractionError::Header("Invalid timestamp format".into()));
    }

    // Safely get and validate the public key
    let public_key = match env::var("DISCORD_PUBLIC_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            eprintln!("DISCORD_PUBLIC_KEY not configured");
            return Err(InteractionError::Config("DISCORD_PUBLIC_KEY not configured".into()));
        }
    };

    // Safely decode public key
    let key_bytes = match hex::decode(&public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => {
            eprintln!("Invalid public key length");
            return Err(InteractionError::Config("Invalid public key length".into()));
        }
        Err(e) => {
            eprintln!("Failed to decode public key: {}", e);
            return Err(InteractionError::Config("Failed to decode public key".into()));
        }
    };

    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("Failed to convert key bytes to array");
            return Err(InteractionError::Config("Failed to convert key bytes to array".into()));
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_array) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to create verifying key: {}", e);
            return Err(InteractionError::Config("Failed to create verifying key".into()));
        }
    };

    // Safely decode signature
    let sig_bytes = match hex::decode(signature_str) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => return Err(InteractionError::Signature("Invalid signature length".into())),
        Err(_) => return Err(InteractionError::Signature("Invalid signature format".into())),
    };

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return Err(InteractionError::Signature("Invalid signature".into())),
    };

    let signature = Signature::from_bytes(&sig_array);

    let message = [timestamp_str.as_bytes(), &body].concat();
    if verifying_key.verify(&message, &signature).is_err() {
        return Err(InteractionError::Signature("Invalid request signature".into()));
    }

    // Step 2: Parse the payload
    let interaction: Interaction = serde_json::from_slice(&body)?;

    // Step 3: Respond based on type
    match interaction.interaction_type {
        1 => Ok(HttpResponse::Ok()
            .content_type("application/json")
            .body(r#"{"type":1}"#)),
        2 => {
            // APPLICATION_COMMAND (slash command)
            if let Some(data) = &interaction.data {
                match data.name.as_str() {
                    "verify" => {
                        // Get Discord user ID
                        let discord_id = if let Some(member) = &interaction.member {
                            member.user.id.clone()
                        } else if let Some(user) = &interaction.user {
                            user.id.clone()
                        } else {
                            return Err(InteractionError::Verification("Cannot determine user ID".into()));
                        };

                        // Validate Discord ID format (should be numeric and reasonable length)
                        if discord_id.is_empty()
                            || discord_id.len() > 20
                            || !discord_id.chars().all(|c| c.is_ascii_digit())
                        {
                            return Err(InteractionError::Verification("Invalid Discord user ID format.".into()));
                        }

                        // Extract the code from command options
                        let code = if let Some(options) = &data.options {
                            options
                                .iter()
                                .find(|opt| opt.name == "code")
                                .and_then(|opt| opt.value.as_i64())
                                .filter(|&v| v >= 0 && v <= 999999) // Validate range
                                .map(|v| format!("{:06}", v))
                        } else {
                            None
                        };

                        if code.is_none() {
                            return Err(InteractionError::Verification("Invalid code format. Please provide a 6-digit code (000000-999999).".into()));
                        }
                        let code = code.unwrap();

                        // Get and validate Minecraft API URL
                        let minecraft_api_url = env::var("MINECRAFT_LINK_API_URL")
                            .map_err(|_| InteractionError::Config("MINECRAFT_LINK_API_URL not configured".into()))?;

                        if minecraft_api_url.is_empty() || (!minecraft_api_url.starts_with("http://") && !minecraft_api_url.starts_with("https://")) {
                            return Err(InteractionError::Config("Invalid MINECRAFT_LINK_API_URL format".into()));
                        }

                        // Get and validate secret key
                        let secret_key = env::var("SECRET_KEY")
                            .map_err(|_| InteractionError::Config("SECRET_KEY not configured".into()))?;
                        if secret_key.is_empty() || secret_key == "default_secret" {
                            return Err(InteractionError::Config("SECRET_KEY not properly configured".into()));
                        }

                        // Create HTTP client with timeout
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_secs(10))
                            .connect_timeout(Duration::from_secs(5))
                            .build()?;

                        let minecraft_response = client
                            .get(&minecraft_api_url)
                            .query(&[
                                ("secret_key", &secret_key),
                                ("code", &code),
                                ("discord_id", &discord_id),
                            ])
                            .send()
                            .await?;

                        let status = minecraft_response.status();
                        let link_data: MinecraftLinkResponse = minecraft_response.json().await?;

                        if link_data.success {
                            let minecraft_username = link_data
                                .minecraft_username
                                .unwrap_or_else(|| "Unknown".to_string());

                            // Validate minecraft username (basic sanitization)
                            let safe_minecraft_username = if minecraft_username.len() <= 16
                                && minecraft_username.chars().all(|c| c.is_alphanumeric() || c == '_')
                            {
                                minecraft_username.clone()
                            } else {
                                "Unknown".to_string()
                            };

                            // Attempt to assign verified role on Discord
                            let guild_id = env::var("DISCORD_GUILD_ID").unwrap_or_default();
                            let role_id = env::var("DISCORD_VERIFIED_ROLE_ID").unwrap_or_default();
                            let bot_token = env::var("DISCORD_BOT_TOKEN").unwrap_or_default();

                            if !guild_id.is_empty()
                                && !role_id.is_empty()
                                && !bot_token.is_empty()
                                && guild_id.chars().all(|c| c.is_ascii_digit())
                                && role_id.chars().all(|c| c.is_ascii_digit())
                            {
                                let discord_url = format!(
                                    "https://discord.com/api/v10/guilds/{}/members/{}/roles/{}",
                                    guild_id, discord_id, role_id
                                );

                                match client
                                    .put(&discord_url)
                                    .header("Authorization", format!("Bot {}", bot_token))
                                    .header("Content-Type", "application/json")
                                    .send()
                                    .await
                                {
                                    Ok(resp) => {
                                        if !resp.status().is_success() {
                                            tracing::error!(
                                                "Failed to assign role: {} - {}",
                                                resp.status(),
                                                resp.text().await.unwrap_or_default()
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!("Error assigning role: {}", err);
                                    }
                                }
                            } else {
                                tracing::warn!("Discord guild/role/token not configured or invalid format; skipping role assignment");
                            }

                            let response = serde_json::json!({
                                "type": 4,
                                "data": {
                                    "embeds": [{
                                        "title": "<:yes:826338663385661481> Account Linked Successfully!",
                                        "description": format!("Your Discord account has been linked to Minecraft account: **{}**", safe_minecraft_username),
                                        "color": 0x00FF00,
                                        "fields": [
                                            {
                                                "name": "Minecraft Username",
                                                "value": safe_minecraft_username,
                                                "inline": true
                                            },
                                            {
                                                "name": "Discord ID",
                                                "value": discord_id,
                                                "inline": true
                                            }
                                        ],
                                        "footer": {
                                            "text": "Your accounts are now linked!"
                                        }
                                    }],
                                    "flags": 64
                                }
                            });
                            Ok(HttpResponse::Ok().json(response))
                        } else {
                            // Failed response from Minecraft server
                            let error_message = link_data.message.unwrap_or_else(|| {
                                format!("Verification failed (HTTP {})", status.as_u16())
                            });

                            // Sanitize error message
                            let safe_error_message = error_message
                                .chars()
                                .filter(|c| {
                                    c.is_alphanumeric()
                                        || c.is_whitespace()
                                        || ".,!?-_()[]:'\"".contains(*c)
                                })
                                .take(500)
                                .collect::<String>();

                            Err(InteractionError::Verification(safe_error_message))
                        }
                    }
                    "link" => {
                        // Provide instructions for the reversed flow
                        let response = serde_json::json!({
                            "type": 4,
                            "data": {
                                "embeds": [{
                                    "title": "🔗 Link Your Accounts",
                                    "description": "To link your Discord and Minecraft accounts, follow these steps:",
                                    "color": 0x5865F2,
                                    "fields": [
                                        {
                                            "name": "Step 1: Join the Server",
                                            "value": "Join the **KAWAISMP** Minecraft server",
                                            "inline": false
                                        },
                                        {
                                            "name": "Step 2: Generate Code",
                                            "value": "Run the command `/link` in the Minecraft server to generate a 6-digit code",
                                            "inline": false
                                        },
                                        {
                                            "name": "Step 3: Verify in Discord",
                                            "value": "Come back here and run `/verify <code>` with your 6-digit code",
                                            "inline": false
                                        }
                                    ],
                                    "footer": {
                                        "text": "The verification code will expire after use"
                                    }
                                }],
                                "flags": 64
                            }
                        });
                        Ok(HttpResponse::Ok().json(response))
                    }
                    _ => {
                        let response = serde_json::json!({
                            "type": 4,
                            "data": {
                                "content": "Unknown command"
                            }
                        });
                        Ok(HttpResponse::Ok().json(response))
                    }
                }
            } else {
                Err(InteractionError::Internal("Missing interaction data".into()))
            }
        }
        _ => {
            let response = serde_json::json!({
                "type": 4,
                "data": {
                    "content": "Hello from Rust API!"
                }
            });
            Ok(HttpResponse::Ok().json(response))
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Get server configuration from environment variables with defaults
    let host = env::var("SERVER_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("SERVER_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8547);

    println!("Listening on {}:{}", host, port);
    HttpServer::new(move || App::new().service(interactions))
        .bind((host.as_str(), port))?
        .run()
        .await
}
