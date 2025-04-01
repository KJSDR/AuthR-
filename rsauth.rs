use std::collections::HashMap;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::thread;
use std::time::Duration;
use rand::Rng;
use argon2::{self, Config};

struct User {
    username: String,
    password_hash: String,
    salt: String,
    last_login: u64,
}

struct AuthSystem {
    users: HashMap<String, User>,
    max_login_attempts: usize,
    lockout_duration_secs: u64,
    failed_attempts: HashMap<String, (usize, u64)>, 
}

impl AuthSystem {
    fn new() -> Self {
        AuthSystem {
            users: HashMap::new(),
            max_login_attempts: 3,
            lockout_duration_secs: 300, 
            failed_attempts: HashMap::new(),
        }
    }

    fn register_user(&mut self, username: &str, password: &str) -> Result<(), String> {
        if self.users.contains_key(username) {
            return Err("Username already exists".to_string());
        }

        let salt = generate_salt();
        let password_hash = hash_password(password, &salt);
        
        let user = User {
            username: username.to_string(),
            password_hash,
            salt,
            last_login: 0,
        };
        
        self.users.insert(username.to_string(), user);
        Ok(())
    }

    fn authenticate(&mut self, username: &str, password: &str) -> Result<bool, String> {
        
        if !self.users.contains_key(username) {
            return Ok(false);
        }
        
        
        if let Some((attempts, timestamp)) = self.failed_attempts.get(username) {
            let now = get_current_time();
            if *attempts >= self.max_login_attempts {
                let time_passed = now - timestamp;
                if time_passed < self.lockout_duration_secs {
                    let remaining = self.lockout_duration_secs - time_passed;
                    return Err(format!("Account is locked. Try again in {} seconds", remaining));
                } else {
                    
                    self.failed_attempts.remove(username);
                }
            }
        }
        
        
        let user = self.users.get(username).unwrap();
        let hash = hash_password(password, &user.salt);
        
        if hash == user.password_hash {
            
            self.failed_attempts.remove(username);
            
            
            let now = get_current_time();
            if let Some(user) = self.users.get_mut(username) {
                user.last_login = now;
            }
            
            Ok(true)
        } else {
            
            let now = get_current_time();
            let entry = self.failed_attempts.entry(username.to_string()).or_insert((0, now));
            entry.0 += 1;
            entry.1 = now;
            
            Ok(false)
        }
    }
    
    fn change_password(&mut self, username: &str, old_password: &str, new_password: &str) -> Result<(), String> {
        
        match self.authenticate(username, old_password) {
            Ok(true) => {
                let user = self.users.get_mut(username).unwrap();
                let salt = generate_salt(); 
                user.password_hash = hash_password(new_password, &salt);
                user.salt = salt;
                Ok(())
            },
            Ok(false) => Err("Current password is incorrect".to_string()),
            Err(e) => Err(e),
        }
    }
}

fn hash_password(password: &str, salt: &str) -> String {
    let config = Config::default();
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();
    
    let hash = argon2::hash_encoded(password_bytes, salt_bytes, &config).unwrap();
    hash
}

fn generate_salt() -> String {
    let mut rng = rand::thread_rng();
    let salt: String = (0..16)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    salt
}

fn get_current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn main() {
    let mut auth_system = AuthSystem::new();
    
    
    let _ = auth_system.register_user("admin", "password123");
    println!("Test user 'admin' created with password 'password123'");
    
    loop {
        println!("\n===== Authentication System =====");
        println!("1. Login");
        println!("2. Register");
        println!("3. Change Password");
        println!("4. Exit");
        print!("Select an option: ");
        io::stdout().flush().unwrap();
        
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).unwrap();
        
        match choice.trim() {
            "1" => {
                print!("Username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                
                print!("Password: ");
                io::stdout().flush().unwrap();
                let mut password = String::new();
                io::stdin().read_line(&mut password).unwrap();
                
                match auth_system.authenticate(username.trim(), password.trim()) {
                    Ok(true) => {
                        println!("Authentication successful!");
                        println!("Welcome, {}!", username.trim());
                        
                        for i in (1..=3).rev() {
                            println!("Logging out in {} seconds...", i);
                            thread::sleep(Duration::from_secs(1));
                        }
                        println!("Logged out.");
                    },
                    Ok(false) => {
                        println!("Invalid username or password");
                    },
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }
            },
            "2" => {
                print!("New username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                
                print!("New password: ");
                io::stdout().flush().unwrap();
                let mut password = String::new();
                io::stdin().read_line(&mut password).unwrap();
                
                match auth_system.register_user(username.trim(), password.trim()) {
                    Ok(_) => println!("User registered successfully!"),
                    Err(e) => println!("Registration error: {}", e),
                }
            },
            "3" => {
                print!("Username: ");
                io::stdout().flush().unwrap();
                let mut username = String::new();
                io::stdin().read_line(&mut username).unwrap();
                
                print!("Current password: ");
                io::stdout().flush().unwrap();
                let mut old_password = String::new();
                io::stdin().read_line(&mut old_password).unwrap();
                
                print!("New password: ");
                io::stdout().flush().unwrap();
                let mut new_password = String::new();
                io::stdin().read_line(&mut new_password).unwrap();
                
                match auth_system.change_password(username.trim(), old_password.trim(), new_password.trim()) {
                    Ok(_) => println!("Password changed successfully!"),
                    Err(e) => println!("Error: {}", e),
                }
            },
            "4" => {
                println!("Exiting...");
                break;
            },
            _ => println!("Invalid option, please try again."),
        }
    }
}
