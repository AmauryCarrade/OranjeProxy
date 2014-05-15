<?php
	
	/**
	 * Simple config manager.
	 * Used for an easier access to the config from everywhere.
	 * 
	 * @author Amaury Carrade
	 * @license GNU General Public License 2+
	 */
	
	class ConfigManager {
		
		static function setConfig(array $config) {
			self::$config = $config;
		}
		
		static function addKey($key, $value, $overwrite == true) {
			
			if($key == NULL || !is_string($key)) {
				throw new InvalidArgumentException('The key is invalid, it must be a non-empty string');
				return false;
			}
			
			if(isset(self::$config[$key]) && !$overwrite) {
				throw new RuntimeException('The key ' . $key . ' already exists and the overwrite mode is set to false');
				return false;
			}
			
			self::$config[$key] = $value;
			
			return true;
		}
		
		static function getConfig($key == NULL) {
			if($key == NULL) {
				return self::$config;
			}
			else {
				if(!isset(self::$config[$key])) {
					throw new InvalidArgumentException('Key ' . $key . ' not found in the stored config.', 404);
					return null;
				}
				else {
					return self::$config[$key];
				}
			}
		}
	}