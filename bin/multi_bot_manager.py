#!/usr/bin/env python

import argparse
import asyncio
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import path_util  # noqa: F401

from hummingbot import init_logging
from hummingbot.client.config.config_crypt import ETHKeyFileSecretManger, BaseSecretsManager
from hummingbot.client.config.config_helpers import (
    ClientConfigAdapter,
    load_client_config_map_from_file,
    read_system_configs_from_yml,
    create_yml_files_legacy,
    load_strategy_config_map_from_file,
)
from hummingbot.client.config.security import Security
from hummingbot.client.hummingbot_application import HummingbotApplication
from hummingbot.client.settings import (
    AllConnectorSettings,
    STRATEGIES_CONF_DIR_PATH,
    SCRIPT_STRATEGIES_PATH,
    SCRIPT_STRATEGY_CONF_DIR_PATH,
)
from hummingbot.client.ui import login_prompt
from hummingbot.client.ui.style import load_style
from hummingbot.core.management.console import start_management_console
from hummingbot.core.utils.async_utils import safe_gather


class BotInstance:
    """
    Represents a single bot instance with its configuration.
    """
    def __init__(self, name: str, account_name: str, config_path: Optional[str] = None, 
                 connectors_path: Optional[str] = None):
        self.name = name
        self.account_name = account_name
        self.config_path = config_path
        self.connectors_path = connectors_path
        self.hummingbot_app: Optional[HummingbotApplication] = None
        self.instance_id: str = str(uuid.uuid4())  # Unique ID for this bot instance
        self.strategy_name: Optional[str] = None
        self.script_config: Optional[str] = None
        self.config_file_name: Optional[str] = None  # Store the original config file name


class MultiBotManager:
    """
    Manager class for running multiple Hummingbot instances with different accounts.
    
    This class allows loading multiple accounts and their corresponding API credentials,
    and creates separate HummingbotApplication instances for each account.
    """

    def __init__(self):
        self.client_config_map: Optional[ClientConfigAdapter] = None
        self.bots: Dict[str, BotInstance] = {}
        self.secrets_manager: Optional[BaseSecretsManager] = None
        self.bots_config_path: Optional[str] = None
        self.config_scan_task: Optional[asyncio.Task] = None

    async def initialize(self, secrets_manager: BaseSecretsManager):
        """
        Initialize the multi-bot manager.
        
        Args:
            secrets_manager: Secrets manager for decrypting configurations
        """
        self.secrets_manager = secrets_manager
        self.client_config_map = load_client_config_map_from_file()
        
        # Initialize logging
        init_logging("hummingbot_logs.yml", self.client_config_map)
        
        # Create yml files if needed
        await create_yml_files_legacy()
        
        # Read system configs
        await read_system_configs_from_yml()
        
        logging.getLogger().info("Initialized MultiBotManager")

    async def start_config_scanning(self, bots_config_path: str, scan_interval: int = 10):
        """
        Start periodic scanning of bots config file for changes.
        
        Args:
            bots_config_path: Path to the bots config file
            scan_interval: Interval in seconds between scans
        """
        self.bots_config_path = bots_config_path
        if self.config_scan_task is not None:
            self.config_scan_task.cancel()
            
        self.config_scan_task = asyncio.create_task(self._scan_config_periodically(scan_interval))
        logging.getLogger().info(f"Started config scanning for {bots_config_path} every {scan_interval} seconds")

    async def _scan_config_periodically(self, scan_interval: int):
        """
        Periodically scan the config file for changes.
        
        Args:
            scan_interval: Interval in seconds between scans
        """
        while True:
            try:
                await asyncio.sleep(scan_interval)
                if self.bots_config_path and os.path.exists(self.bots_config_path):
                    await self._check_for_config_changes()
            except asyncio.CancelledError:
                logging.getLogger().info("Config scanning task cancelled")
                break
            except Exception as e:
                logging.getLogger().error(f"Error during config scanning: {e}")

    async def _check_for_config_changes(self):
        """Check for changes in the bots config file."""
        try:
            bots_config = load_bots_config(self.bots_config_path)
            
            # Get current bot accounts
            current_bot_accounts = set(self.bots.keys())
            
            # Get configured bot accounts
            configured_bot_accounts = set()
            bots_to_stop = set()
            
            # Process each configured bot
            for bot_config in bots_config:
                account_name = bot_config.get('account')
                stop_flag = bot_config.get('stop', False)
                
                if account_name:
                    configured_bot_accounts.add(account_name)
                    
                    # Handle stop flag
                    if stop_flag:
                        bots_to_stop.add(account_name)
                    # Handle new bots
                    elif account_name not in current_bot_accounts:
                        # Create new bot
                        config_file = bot_config.get('config_file')
                        script_conf = bot_config.get('script_conf')
                        connectors_path = bot_config.get('connectors_path')
                        
                        await self.create_bot(account_name, config_file, script_conf, connectors_path)
                        logging.getLogger().info(f"Added new bot {account_name} from config")
            
            # Stop bots with stop flag
            for account_name in bots_to_stop:
                if account_name in self.bots:
                    await self.stop_bot(account_name)
                    logging.getLogger().info(f"Stopped bot {account_name} due to stop flag")
            
            # Remove bots that are no longer in config (and not marked for stop)
            bots_to_remove = current_bot_accounts - configured_bot_accounts - bots_to_stop
            for account_name in bots_to_remove:
                if account_name in self.bots:
                    await self.stop_bot(account_name)
                    logging.getLogger().info(f"Removed bot {account_name} as it's no longer in config")
                        
        except Exception as e:
            logging.getLogger().error(f"Error checking config changes: {e}")

    async def create_bot(self, 
                         account_name: str,
                         config_file_name: Optional[str] = None,
                         script_conf: Optional[str] = None,
                         connectors_path: Optional[str] = None,
                         headless: bool = True) -> Optional[HummingbotApplication]:
        """
        Create a new Hummingbot instance for a specific account.
        
        Args:
            account_name: Name of the account to use (also used as bot name)
            config_file_name: Strategy config file name
            script_conf: Script config file name
            connectors_path: Custom path for connector configurations
            headless: Whether to run in headless mode
            
        Returns:
            HummingbotApplication instance or None if failed
        """
        bot_name = account_name  # Use account name as bot name
        
        if bot_name in self.bots:
            raise ValueError(f"Bot {bot_name} already exists")
            
        try:
            # Create bot instance
            bot_instance = BotInstance(bot_name, account_name, config_file_name, connectors_path)
            bot_instance.config_file_name = config_file_name  # Store for reference
            
            # Set custom connectors path for this instance if specified
            if connectors_path:
                Security.set_instance_connectors_path(bot_instance.instance_id, connectors_path)
            
            # Login with the global secrets manager for this specific instance
            if not Security.login(self.secrets_manager, bot_instance.instance_id):
                raise ValueError(f"Failed to login with provided credentials")
                
            await Security.wait_til_decryption_done(bot_instance.instance_id)
            
            # Create the hummingbot application for this account
            hb = HummingbotApplication.main_application(
                client_config_map=self.client_config_map, 
                headless_mode=headless
            )
            
            # Initialize paper trade settings
            AllConnectorSettings.initialize_paper_trade_settings(
                self.client_config_map.paper_trade.paper_trade_exchanges
            )
            
            # Load and start strategy if provided
            if config_file_name is not None:
                success = await self._load_and_start_strategy(bot_instance, hb, config_file_name, script_conf)
                if not success:
                    logging.getLogger().error(f"Failed to load strategy for bot {bot_name}.")
                    # We'll continue anyway as the bot might be started later
            
            # Store reference to this bot
            bot_instance.hummingbot_app = hb
            self.bots[bot_name] = bot_instance
            
            logging.getLogger().info(f"Created bot {bot_name} with instance ID {bot_instance.instance_id}")
            return hb
                
        except Exception as e:
            logging.getLogger().error(f"Failed to create bot {bot_name}: {e}")
            return None

    async def _load_and_start_strategy(self, bot_instance: BotInstance, hb: HummingbotApplication, 
                                       config_file_name: str, script_conf: Optional[str] = None) -> bool:
        """
        Load and start strategy based on file type and mode.
        
        Args:
            bot_instance: The bot instance
            hb: The hummingbot application
            config_file_name: Strategy config file name
            script_conf: Script config file name
            
        Returns:
            bool: True if strategy loaded and started successfully
        """
        if config_file_name.endswith(".py"):
            # Script strategy
            strategy_name = config_file_name.replace(".py", "")
            strategy_config_file = script_conf  # Optional config file for script

            # Validate that the script file exists
            script_file_path = SCRIPT_STRATEGIES_PATH / config_file_name
            if not script_file_path.exists():
                logging.getLogger().error(f"Script file not found: {script_file_path}")
                return False

            # Validate that the script config file exists if provided
            if strategy_config_file:
                script_config_path = SCRIPT_STRATEGY_CONF_DIR_PATH / strategy_config_file
                if not script_config_path.exists():
                    logging.getLogger().error(f"Script config file not found: {script_config_path}")
                    return False

            # Set strategy_file_name to config file if provided, otherwise script file (matching start_command logic)
            hb.strategy_file_name = strategy_config_file.split(".")[0] if strategy_config_file else strategy_name
            hb.strategy_name = strategy_name
            
            # Store for later use
            bot_instance.strategy_name = strategy_name
            if strategy_config_file:
                bot_instance.script_config = strategy_config_file

            logging.getLogger().info(f"Starting script strategy: {strategy_name}")
            success = await hb.trading_core.start_strategy(
                strategy_name,
                strategy_config_file,  # Pass config file path if provided
                hb.strategy_file_name + (".yml" if strategy_config_file else ".py")  # Full file name for strategy
            )
            if not success:
                logging.getLogger().error("Failed to start strategy")
                return False
        else:
            # Regular strategy with YAML config
            hb.strategy_file_name = config_file_name.split(".")[0]  # Remove .yml extension
            
            # Store for later use
            bot_instance.strategy_name = hb.strategy_file_name

            try:
                strategy_config = await load_strategy_config_map_from_file(
                    STRATEGIES_CONF_DIR_PATH / config_file_name
                )
            except FileNotFoundError:
                logging.getLogger().error(f"Strategy config file not found: {STRATEGIES_CONF_DIR_PATH / config_file_name}")
                return False
            except Exception as e:
                logging.getLogger().error(f"Error loading strategy config file: {e}")
                return False

            strategy_name = (
                strategy_config.strategy
                if isinstance(strategy_config, ClientConfigAdapter)
                else strategy_config.get("strategy").value
            )
            hb.trading_core.strategy_name = strategy_name

            logging.getLogger().info(f"Starting regular strategy: {strategy_name}")
            success = await hb.trading_core.start_strategy(
                strategy_name,
                strategy_config,
                config_file_name
            )
            if not success:
                logging.getLogger().error("Failed to start strategy")
                return False

        return True

    async def start_bot(self, bot_name: str):
        """
        Start a specific bot.
        
        Args:
            bot_name: Name of the bot to start
        """
        if bot_name not in self.bots:
            raise ValueError(f"Bot {bot_name} not found")
            
        bot = self.bots[bot_name]
        # TODO: Implement actual bot start logic
        logging.getLogger().info(f"Started bot {bot_name}")

    async def stop_bot(self, bot_name: str):
        """
        Stop a specific bot and release resources.
        
        Args:
            bot_name: Name of the bot to stop
        """
        if bot_name not in self.bots:
            raise ValueError(f"Bot {bot_name} not found")
            
        bot = self.bots[bot_name]
        
        try:
            # Stop the strategy if running
            if bot.hummingbot_app and bot.hummingbot_app.trading_core._strategy_running:
                await bot.hummingbot_app.trading_core.stop_strategy()
                
            # Close the hummingbot app
            if bot.hummingbot_app:
                # Stop the app's run loop
                # Note: In a real implementation, you would need to properly stop the app's event loop
                pass
                
            # Clean up the bot instance
            del self.bots[bot_name]
            
            logging.getLogger().info(f"Stopped bot {bot_name} and released resources")
        except Exception as e:
            logging.getLogger().error(f"Error stopping bot {bot_name}: {e}")

    async def stop_all_bots(self):
        """Stop all bots and release resources."""
        bot_names = list(self.bots.keys())
        for bot_name in bot_names:
            await self.stop_bot(bot_name)

    async def run_bots(self):
        """
        Run all bots concurrently.
        """
        if not self.bots:
            logging.getLogger().warning("No bots to run")
            return
            
        tasks = []
        for bot_name, bot_instance in self.bots.items():
            if bot_instance.hummingbot_app:
                tasks.append(bot_instance.hummingbot_app.run())
                logging.getLogger().info(f"Added bot {bot_name} to run loop")
            
        # Also start management console if enabled
        if self.client_config_map.debug_console:
            management_port: int = 8211
            tasks.append(start_management_console(locals(), host="localhost", port=management_port))
            
        await safe_gather(*tasks)

    def get_bot(self, bot_name: str) -> Optional[HummingbotApplication]:
        """
        Get a specific bot instance.
        
        Args:
            bot_name: Name of the bot
            
        Returns:
            HummingbotApplication instance or None if not found
        """
        bot_instance = self.bots.get(bot_name)
        return bot_instance.hummingbot_app if bot_instance else None

    def list_bots(self) -> List[str]:
        """
        List all bot names.
        
        Returns:
            List of bot names
        """
        return list(self.bots.keys())

    def stop_config_scanning(self):
        """Stop the config scanning task."""
        if self.config_scan_task is not None:
            self.config_scan_task.cancel()
            self.config_scan_task = None
            logging.getLogger().info("Stopped config scanning")


def load_bots_config(config_file: str) -> List[Dict]:
    """
    Load bot configurations from a JSON file.
    
    Args:
        config_file: Path to the configuration file
        
    Returns:
        List of bot configuration dictionaries
    """
    try:
        with open(config_file, 'r') as f:
            config = json.load(f)
        return config.get('bots', [])
    except Exception as e:
        logging.getLogger().error(f"Failed to load bots config from {config_file}: {e}")
        return []


class MultiBotCmdlineParser(argparse.ArgumentParser):
    def __init__(self):
        super().__init__()
        self.add_argument("--bots-config",
                          type=str,
                          required=False,
                          help="Specify a file containing bot configurations.")
        self.add_argument("--config-password", "-p",
                          type=str,
                          required=False,
                          help="Specify the password to unlock your encrypted files.")
        self.add_argument("--scan-interval",
                          type=int,
                          default=10,
                          help="Interval in seconds to scan for config changes (default: 10)")
        self.add_argument("--debug-console",
                          type=bool,
                          nargs='?',
                          const=True,
                          default=False,
                          help="Enable debug console.")


async def quick_start(args: argparse.Namespace, secrets_manager: BaseSecretsManager):
    """Start multiple Hummingbot instances using unified approach."""
    
    # Create and initialize manager
    manager = MultiBotManager()
    await manager.initialize(secrets_manager)
    
  
    # Start config scanning first to monitor for changes
    await manager.start_config_scanning(args.bots_config, args.scan_interval)
    
    # Keep the process running indefinitely
    try:
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logging.getLogger().info("Received keyboard interrupt. Shutting down...")
    finally:
        # Stop config scanning when done
        manager.stop_config_scanning()
        # Stop all bots and release resources
        await manager.stop_all_bots()


def main():
    parser = MultiBotCmdlineParser()
    args = parser.parse_args()
    
    # Parse environment variables
    if args.config_password is None and len(os.environ.get("CONFIG_PASSWORD", "")) > 0:
        args.config_password = os.environ["CONFIG_PASSWORD"]

    # If no password is given from the command line, prompt for one.
    secrets_manager_cls = ETHKeyFileSecretManger
    client_config_map = load_client_config_map_from_file()
    if args.config_password is None:
        secrets_manager = login_prompt(secrets_manager_cls, style=load_style(client_config_map))
        if not secrets_manager:
            return
    else:
        secrets_manager = secrets_manager_cls(args.config_password)

    try:
        ev_loop: asyncio.AbstractEventLoop = asyncio.get_running_loop()
    except RuntimeError:
        ev_loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        asyncio.set_event_loop(ev_loop)

    ev_loop.run_until_complete(quick_start(args, secrets_manager))


if __name__ == "__main__":
    main()