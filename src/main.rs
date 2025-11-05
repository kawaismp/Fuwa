use actix_web::{App, HttpRequest, HttpResponse, HttpServer, Responder, post, web};
use dotenvy::dotenv;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;
use std::env;
use std::time::Duration;

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

#[post("/interactions")]
async fn interactions(req: HttpRequest, body: web::Bytes) -> impl Responder {
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
        return HttpResponse::Unauthorized().body("Missing signature or timestamp");
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
            return HttpResponse::Unauthorized().body("Request timestamp too old or invalid");
        }
    } else {
        return HttpResponse::Unauthorized().body("Invalid timestamp format");
    }

    // Safely get and validate the public key
    let public_key = match env::var("DISCORD_PUBLIC_KEY") {
        Ok(key) if !key.is_empty() => key,
        _ => {
            eprintln!("DISCORD_PUBLIC_KEY not configured");
            return HttpResponse::InternalServerError().body("Server configuration error");
        }
    };

    // Safely decode public key
    let key_bytes = match hex::decode(&public_key) {
        Ok(bytes) if bytes.len() == 32 => bytes,
        Ok(_) => {
            eprintln!("Invalid public key length");
            return HttpResponse::InternalServerError().body("Server configuration error");
        }
        Err(e) => {
            eprintln!("Failed to decode public key: {}", e);
            return HttpResponse::InternalServerError().body("Server configuration error");
        }
    };

    let key_array: [u8; 32] = match key_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            eprintln!("Failed to convert key bytes to array");
            return HttpResponse::InternalServerError().body("Server configuration error");
        }
    };

    let verifying_key = match VerifyingKey::from_bytes(&key_array) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("Failed to create verifying key: {}", e);
            return HttpResponse::InternalServerError().body("Server configuration error");
        }
    };

    // Safely decode signature
    let sig_bytes = match hex::decode(signature_str) {
        Ok(bytes) if bytes.len() == 64 => bytes,
        Ok(_) => return HttpResponse::Unauthorized().body("Invalid signature length"),
        Err(_) => return HttpResponse::Unauthorized().body("Invalid signature format"),
    };

    let sig_array: [u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return HttpResponse::Unauthorized().body("Invalid signature"),
    };

    let signature = Signature::from_bytes(&sig_array);

    let message = [timestamp_str.as_bytes(), &body].concat();
    if verifying_key.verify(&message, &signature).is_err() {
        return HttpResponse::Unauthorized().body("Invalid request signature");
    }

    // Step 2: Parse the payload
    let Ok(interaction): Result<Interaction, _> = serde_json::from_slice(&body) else {
        return HttpResponse::BadRequest().body("Invalid JSON");
    };

    // Step 3: Respond based on type
    match interaction.interaction_type {
        1 => {
            // PING -> respond with PONG
            HttpResponse::Ok()
                .content_type("application/json")
                .body(r#"{"type":1}"#)
        }
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
                            return HttpResponse::BadRequest().body("Cannot determine user ID");
                        };

                        // Validate Discord ID format (should be numeric and reasonable length)
                        if discord_id.is_empty()
                            || discord_id.len() > 20
                            || !discord_id.chars().all(|c| c.is_ascii_digit())
                        {
                            let response = serde_json::json!({
                                "type": 4,
                                "data": {
                                    "embeds": [{
                                        "title": ":no: Verification Failed",
                                        "description": "Invalid Discord user ID format.",
                                        "color": 0xFF0000
                                    }],
                                    "flags": 64
                                }
                            });
                            return HttpResponse::Ok().json(response);
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

                        let Some(code) = code else {
                            let response = serde_json::json!({
                                "type": 4,
                                "data": {
                                    "embeds": [{
                                        "title": ":no: Verification Failed",
                                        "description": "Invalid code format. Please provide a 6-digit code (000000-999999).",
                                        "color": 0xFF0000
                                    }],
                                    "flags": 64
                                }
                            });
                            return HttpResponse::Ok().json(response);
                        };

                        // Get and validate Minecraft API URL
                        let minecraft_api_url = match env::var("MINECRAFT_LINK_API_URL") {
                            Ok(url) if !url.is_empty() => url,
                            _ => {
                                eprintln!("MINECRAFT_LINK_API_URL not configured");
                                let response = serde_json::json!({
                                    "type": 4,
                                    "data": {
                                        "embeds": [{
                                            "title": ":no: Configuration Error",
                                            "description": "Server is not properly configured. Please contact an administrator.",
                                            "color": 0xFF0000
                                        }],
                                        "flags": 64
                                    }
                                });
                                return HttpResponse::Ok().json(response);
                            }
                        };

                        // Validate URL format
                        if !minecraft_api_url.starts_with("http://")
                            && !minecraft_api_url.starts_with("https://")
                        {
                            eprintln!(
                                "Invalid MINECRAFT_LINK_API_URL format: {}",
                                minecraft_api_url
                            );
                            let response = serde_json::json!({
                                "type": 4,
                                "data": {
                                    "embeds": [{
                                        "title": ":no: Configuration Error",
                                        "description": "Server is not properly configured. Please contact an administrator.",
                                        "color": 0xFF0000
                                    }],
                                    "flags": 64
                                }
                            });
                            return HttpResponse::Ok().json(response);
                        }

                        // Get and validate secret key - MUST be configured, no default
                        let secret_key = match env::var("SECRET_KEY") {
                            Ok(key) if !key.is_empty() && key != "default_secret" => key,
                            _ => {
                                eprintln!("SECRET_KEY not properly configured");
                                let response = serde_json::json!({
                                    "type": 4,
                                    "data": {
                                        "embeds": [{
                                            "title": ":no: Configuration Error",
                                            "description": "Server is not properly configured. Please contact an administrator.",
                                            "color": 0xFF0000
                                        }],
                                        "flags": 64
                                    }
                                });
                                return HttpResponse::Ok().json(response);
                            }
                        };

                        // Create HTTP client with timeout
                        let client = match reqwest::Client::builder()
                            .timeout(Duration::from_secs(10))
                            .connect_timeout(Duration::from_secs(5))
                            .build()
                        {
                            Ok(client) => client,
                            Err(e) => {
                                eprintln!("Failed to create HTTP client: {}", e);
                                let response = serde_json::json!({
                                    "type": 4,
                                    "data": {
                                        "embeds": [{
                                            "title": ":no: Server Error",
                                            "description": "An internal error occurred. Please try again later.",
                                            "color": 0xFF0000
                                        }],
                                        "flags": 64
                                    }
                                });
                                return HttpResponse::Ok().json(response);
                            }
                        };

                        let minecraft_response = client
                            .get(&minecraft_api_url)
                            .query(&[
                                ("secret_key", &secret_key),
                                ("code", &code),
                                ("discord_id", &discord_id),
                            ])
                            .send()
                            .await;

                        match minecraft_response {
                            Ok(resp) if resp.status().is_success() => {
                                // Parse response from Minecraft server
                                match resp.json::<MinecraftLinkResponse>().await {
                                    Ok(link_data) if link_data.success => {
                                        let minecraft_username = link_data
                                            .minecraft_username
                                            .unwrap_or_else(|| "Unknown".to_string());

                                        // Validate minecraft username (basic sanitization)
                                        let safe_minecraft_username = if minecraft_username.len()
                                            <= 16
                                            && minecraft_username
                                                .chars()
                                                .all(|c| c.is_alphanumeric() || c == '_')
                                        {
                                            minecraft_username.clone()
                                        } else {
                                            "Unknown".to_string()
                                        };

                                        // Attempt to assign verified role on Discord
                                        let guild_id =
                                            env::var("DISCORD_GUILD_ID").unwrap_or_default();
                                        let role_id = env::var("DISCORD_VERIFIED_ROLE_ID")
                                            .unwrap_or_default();
                                        let bot_token =
                                            env::var("DISCORD_BOT_TOKEN").unwrap_or_default();

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

                                            // Send PUT request to add role (Discord returns 204 No Content on success)
                                            match client
                                                .put(&discord_url)
                                                .header(
                                                    "Authorization",
                                                    format!("Bot {}", bot_token),
                                                )
                                                .header("Content-Type", "application/json")
                                                .send()
                                                .await
                                            {
                                                Ok(resp) => {
                                                    if !resp.status().is_success() {
                                                        // Role assignment failed; continue without failing the command
                                                        eprintln!(
                                                            "Failed to assign role: {} - {}",
                                                            resp.status(),
                                                            resp.text().await.unwrap_or_default()
                                                        );
                                                    }
                                                }
                                                Err(err) => {
                                                    eprintln!("Error assigning role: {}", err);
                                                }
                                            }
                                        } else {
                                            eprintln!(
                                                "Discord guild/role/token not configured or invalid format; skipping role assignment"
                                            );
                                        }

                                        let response = serde_json::json!({
                                            "type": 4,
                                            "data": {
                                                "embeds": [{
                                                    "title": ":yes: Account Linked Successfully!",
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
                                        HttpResponse::Ok().json(response)
                                    }
                                    Ok(link_data) => {
                                        // Failed response from Minecraft server
                                        let error_message =
                                            link_data.message.unwrap_or_else(|| {
                                                "Unknown error occurred".to_string()
                                            });

                                        // Sanitize error message to prevent injection
                                        let safe_error_message = error_message
                                            .chars()
                                            .filter(|c| {
                                                c.is_alphanumeric()
                                                    || c.is_whitespace()
                                                    || ".,!?-_()[]".contains(*c)
                                            })
                                            .take(500) // Limit length
                                            .collect::<String>();

                                        let response = serde_json::json!({
                                            "type": 4,
                                            "data": {
                                                "embeds": [{
                                                    "title": ":no: Verification Failed",
                                                    "description": safe_error_message,
                                                    "color": 0xFF0000,
                                                    "fields": [
                                                        {
                                                            "name": "What to do?",
                                                            "value": "1. Join the KAWAISMP Minecraft server\n2. Run `/link` to generate a new code\n3. Use `/verify <code>` here in Discord",
                                                            "inline": false
                                                        }
                                                    ]
                                                }],
                                                "flags": 64
                                            }
                                        });
                                        HttpResponse::Ok().json(response)
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "Failed to parse Minecraft server response: {}",
                                            e
                                        );
                                        let response = serde_json::json!({
                                            "type": 4,
                                            "data": {
                                                "embeds": [{
                                                    "title": ":no: Verification Failed",
                                                    "description": "Failed to parse response from Minecraft server. Please try again later.",
                                                    "color": 0xFF0000
                                                }],
                                                "flags": 64
                                            }
                                        });
                                        HttpResponse::Ok().json(response)
                                    }
                                }
                            }
                            Ok(resp) => {
                                // Non-success status code
                                let status = resp.status();
                                eprintln!("Minecraft server error: {}", status);
                                let response = serde_json::json!({
                                    "type": 4,
                                    "data": {
                                        "embeds": [{
                                            "title": ":no: Verification Failed",
                                            "description": "The Minecraft server is currently unavailable. Please try again later.",
                                            "color": 0xFF0000
                                        }],
                                        "flags": 64
                                    }
                                });
                                HttpResponse::Ok().json(response)
                            }
                            Err(e) => {
                                // Request failed
                                eprintln!("Failed to connect to Minecraft server: {}", e);
                                let response = serde_json::json!({
                                    "type": 4,
                                    "data": {
                                        "embeds": [{
                                            "title": ":no: Connection Failed",
                                            "description": "Could not connect to Minecraft server. Please try again later.",
                                            "color": 0xFF0000
                                        }],
                                        "flags": 64
                                    }
                                });
                                HttpResponse::Ok().json(response)
                            }
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
                        HttpResponse::Ok().json(response)
                    }
                    _ => {
                        let response = serde_json::json!({
                            "type": 4,
                            "data": {
                                "content": "Unknown command"
                            }
                        });
                        HttpResponse::Ok().json(response)
                    }
                }
            } else {
                HttpResponse::BadRequest().body("Missing interaction data")
            }
        }
        _ => {
            // Other interaction types
            let response = serde_json::json!({
                "type": 4,
                "data": {
                    "content": "Hello from Rust API!"
                }
            });
            HttpResponse::Ok().json(response)
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    println!("Listening on 0.0.0.0:8080");
    HttpServer::new(move || App::new().service(interactions))
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
}
