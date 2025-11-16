use dotenvy::dotenv;
use serde::{Deserialize, Serialize};
use std::env;

const DISCORD_API_VERSION: &str = "v10";
const COMMAND_TYPE_CHAT_INPUT: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct Command {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    name: String,
    #[serde(rename = "type")]
    command_type: u8,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<Vec<serde_json::Value>>,
}

struct DiscordConfig {
    app_id: String,
    guild_id: String,
    bot_token: String,
}

impl DiscordConfig {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            app_id: env::var("DISCORD_APP_ID").map_err(|_| "Missing DISCORD_APP_ID")?,
            guild_id: env::var("DISCORD_GUILD_ID").map_err(|_| "Missing DISCORD_GUILD_ID")?,
            bot_token: env::var("DISCORD_BOT_TOKEN").map_err(|_| "Missing DISCORD_BOT_TOKEN")?,
        })
    }

    fn commands_url(&self) -> String {
        format!(
            "https://discord.com/api/{}/applications/{}/guilds/{}/commands",
            DISCORD_API_VERSION, self.app_id, self.guild_id
        )
    }

    fn auth_header(&self) -> String {
        format!("Bot {}", self.bot_token)
    }
}

fn fetch_existing_commands(
    client: &reqwest::blocking::Client,
    config: &DiscordConfig,
) -> Result<Vec<Command>, Box<dyn std::error::Error>> {
    println!("Checking existing commands...");

    let commands: Vec<Command> = client
        .get(&config.commands_url())
        .header("Authorization", config.auth_header())
        .send()?
        .json()?;

    println!("Found {} existing commands", commands.len());
    for cmd in &commands {
        println!(
            "  - {} (ID: {})",
            cmd.name,
            cmd.id.as_ref().unwrap_or(&"N/A".to_string())
        );
    }

    Ok(commands)
}

fn unregister_command(
    client: &reqwest::blocking::Client,
    config: &DiscordConfig,
    command: &Command,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(id) = &command.id else {
        println!("  - Skipping '{}' with missing ID", command.name);
        return Ok(());
    };

    let delete_url = format!("{}/{}", config.commands_url(), id);
    let response = client
        .delete(&delete_url)
        .header("Authorization", config.auth_header())
        .send()?;

    if response.status().is_success() {
        println!("✓ Unregistered '{}' (ID: {})", command.name, id);
        Ok(())
    } else {
        let status = response.status();
        let error_text = response.text()?;
        eprintln!(
            "✗ Failed to unregister '{}' (ID: {}): {}",
            command.name, id, status
        );
        eprintln!("  Error: {}", error_text);
        Err(format!("Failed to unregister command: {}", status).into())
    }
}

fn unregister_commands_by_name(
    client: &reqwest::blocking::Client,
    config: &DiscordConfig,
    commands: &[Command],
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let matching_commands: Vec<_> = commands.iter().filter(|cmd| cmd.name == name).collect();

    if matching_commands.is_empty() {
        return Ok(());
    }

    println!(
        "\nFound {} existing '{}' command(s), unregistering...",
        matching_commands.len(),
        name
    );

    for cmd in matching_commands {
        unregister_command(client, config, cmd)?;
    }

    Ok(())
}

fn register_command(
    client: &reqwest::blocking::Client,
    config: &DiscordConfig,
    command: &Command,
) -> Result<Command, Box<dyn std::error::Error>> {
    println!("\nRegistering '{}' command...", command.name);

    let response = client
        .post(&config.commands_url())
        .header("Authorization", config.auth_header())
        .header("Content-Type", "application/json")
        .json(command)
        .send()?;

    if response.status().is_success() {
        let registered: Command = response.json()?;
        println!("✓ Successfully registered '{}' command!", command.name);
        if let Some(id) = &registered.id {
            println!("  Command ID: {}", id);
        }
        Ok(registered)
    } else {
        let status = response.status();
        let error_text = response.text()?;
        eprintln!("✗ Failed to register command:");
        eprintln!("  Status: {}", status);
        eprintln!("  Error: {}", error_text);
        Err(format!("Failed to register command: {}", status).into())
    }
}

fn create_link_command() -> Command {
    Command {
        id: None,
        name: "link".to_string(),
        command_type: COMMAND_TYPE_CHAT_INPUT,
        description: "Link your Minecraft account to your Discord account".to_string(),
        options: None,
    }
}

fn create_verify_command() -> Command {
    Command {
        id: None,
        name: "verify".to_string(),
        command_type: COMMAND_TYPE_CHAT_INPUT,
        description: "Verify your minecraft account to your Discord account".to_string(),
        options: Some(vec![
            serde_json::json!({
                "name": "code",
                "description": "The 6-digit verification code from the Minecraft server",
                "type": 4, // INTEGER type
                "required": true,
            })
        ]),
    }
}

fn create_forgot_password_command() -> Command {
    Command {
        id: None,
        name: "forgot-password".to_string(),
        command_type: COMMAND_TYPE_CHAT_INPUT,
        description: "Reset your password via Discord OAuth2 authentication".to_string(),
        options: None,
    }
}

fn create_reset_password_command() -> Command {
    Command {
        id: None,
        name: "reset-password".to_string(),
        command_type: COMMAND_TYPE_CHAT_INPUT,
        description: "Reset your password via Discord OAuth2 authentication".to_string(),
        options: None,
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv().ok();

    let config = DiscordConfig::from_env()?;
    let client = reqwest::blocking::Client::new();

    // Fetch existing commands
    let existing_commands = fetch_existing_commands(&client, &config)?;

    // Unregister any existing commands
    unregister_commands_by_name(&client, &config, &existing_commands, "link")?;
    unregister_commands_by_name(&client, &config, &existing_commands, "verify")?;
    unregister_commands_by_name(&client, &config, &existing_commands, "forgot-password")?;
    unregister_commands_by_name(&client, &config, &existing_commands, "reset-password")?;

    // Register the commands
    let link_command = create_link_command();
    register_command(&client, &config, &link_command)?;
    let verify_command = create_verify_command();
    register_command(&client, &config, &verify_command)?;
    let forgot_password_command = create_forgot_password_command();
    register_command(&client, &config, &forgot_password_command)?;
    let reset_password_command = create_reset_password_command();
    register_command(&client, &config, &reset_password_command)?;

    Ok(())
}
