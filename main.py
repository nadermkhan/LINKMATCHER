import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import pandas as pd
import os
from threading import Thread
import json
import hashlib
from datetime import datetime, timedelta
import base64
from cryptography.fernet import Fernet
import sys

class LicenseManager:
    def __init__(self):
        self.license_file = "license.key"
        self.secret = b"NADERMAHBUBKHAN34322$$$$$433n6463642"
        self.secret_key = self._get_fernet_key()
        
    def encrypt_decrypt(self, text, key):
        """Simple XOR encryption/decryption"""
        result = ''
        key = key.decode() if isinstance(key, bytes) else key
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
        
    def validate_license(self, key_string):
        """Validate the license key with support for minute/hour based licenses"""
        try:
            # Decode from base64
            decoded = base64.b64decode(key_string).decode('utf-8')
            
            # Decrypt
            decrypted = self.encrypt_decrypt(decoded, self.secret_key)
            
            # Parse JSON
            license_data = json.loads(decrypted)
            
            # Verify checksum
            checksum = license_data.get('checksum', '')
            data_str = f"{license_data.get('user_name', '')}{license_data.get('expiry_date', '')}{license_data.get('valid', '')}"
            expected_checksum = hashlib.md5(data_str.encode()).hexdigest()
            
            if checksum != expected_checksum:
                return False, "Invalid license key (checksum mismatch)"
            
            # Check if key is valid
            if not license_data.get('valid', False):
                return False, "Invalid license key"
            
            # Check expiry date
            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            now = datetime.now()
            
            if now > expiry_date:
                return False, f"License expired on {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}"
            
            # Check machine binding (optional)
            if license_data.get('machine_id'):
                current_machine_id = self._get_machine_id()
                if license_data['machine_id'] != current_machine_id:
                    return False, "License is not valid for this machine"
            
            # Calculate time remaining
            time_left = expiry_date - now
            total_seconds = int(time_left.total_seconds())
            
            # Format time remaining message
            if total_seconds < 60:
                time_msg = f"{total_seconds} seconds"
            elif total_seconds < 3600:
                minutes = total_seconds // 60
                seconds = total_seconds % 60
                time_msg = f"{minutes} minutes, {seconds} seconds"
            elif total_seconds < 86400:
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                time_msg = f"{hours} hours, {minutes} minutes"
            else:
                days = total_seconds // 86400
                hours = (total_seconds % 86400) // 3600
                if days > 0:
                    time_msg = f"{days} days, {hours} hours"
                else:
                    time_msg = f"{hours} hours"
            
            # Get license type
            license_type = license_data.get('license_type', 'Standard License')
            
            return True, f"{license_type} - Valid for {time_msg} (until {expiry_date.strftime('%Y-%m-%d %H:%M')})"
            
        except Exception as e:
            return False, "Invalid or corrupted license key"
    
    def _get_fernet_key(self):
        """Generate Fernet key from secret"""
        return base64.urlsafe_b64encode(hashlib.sha256(self.secret).digest())
    
    def _get_machine_id(self):
        """Get unique machine identifier"""
        import platform
        import socket
        
        try:
            # Combine hostname and platform for machine ID
            hostname = socket.gethostname()
            platform_info = platform.platform()
            machine_string = f"{hostname}-{platform_info}"
            return hashlib.sha256(machine_string.encode()).hexdigest()[:16]
        except:
            return "default"
    
    def save_license(self, key_string):
        """Save license key to file"""
        with open(self.license_file, 'w') as f:
            f.write(key_string)
    
    def load_license(self):
        """Load license key from file"""
        if os.path.exists(self.license_file):
            with open(self.license_file, 'r') as f:
                return f.read().strip()
        return None

class LicenseDialog:
    def __init__(self, parent, license_manager):
        self.license_manager = license_manager
        self.result = None
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("License Activation")
        self.dialog.geometry("500x300")
        self.dialog.resizable(False, False)
        
        # Make dialog modal
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Center the dialog
        self.dialog.update_idletasks()
        x = (self.dialog.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (300 // 2)
        self.dialog.geometry(f"+{x}+{y}")
        
        # Create widgets
        self.create_widgets()
        
        # Handle window close
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Enter License Key", 
                               font=('Helvetica', 14, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Instructions
        info_label = ttk.Label(main_frame, 
                              text="Please enter your license key to activate the application.",
                              wraplength=450)
        info_label.pack(pady=(0, 10))
        
        # License key input
        ttk.Label(main_frame, text="License Key:").pack(anchor=tk.W, pady=(10, 5))
        
        # Text widget for multi-line key input
        self.key_text = tk.Text(main_frame, height=5, width=55)
        self.key_text.pack(pady=(0, 10))
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Activate", 
                  command=self.validate_key).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", 
                  command=self.on_close).pack(side=tk.LEFT, padx=5)
        
        # Status label
        self.status_label = ttk.Label(main_frame, text="", foreground="red")
        self.status_label.pack(pady=10)
    
    def validate_key(self):
        key_string = self.key_text.get("1.0", tk.END).strip()
        
        if not key_string:
            self.status_label.config(text="Please enter a license key", foreground="red")
            return
        
        # Validate the key
        is_valid, message = self.license_manager.validate_license(key_string)
        
        if is_valid:
            self.license_manager.save_license(key_string)
            self.result = True
            messagebox.showinfo("Success", f"License activated successfully!\n\n{message}")
            self.dialog.destroy()
        else:
            self.status_label.config(text=message, foreground="red")
    
    def on_close(self):
        self.result = False
        self.dialog.destroy()

class CSVMatcherGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CSV LinkedIn URL Matcher (Licensed)")
        self.root.geometry("600x450")
        
        # Initialize license manager
        self.license_manager = LicenseManager()
        
        # Check license on startup
        if not self.check_license():
            self.root.destroy()
            return
        
        # Variables to store file paths
        self.main_file_path = tk.StringVar()
        self.new_table_path = tk.StringVar()
        self.output_path = tk.StringVar(value="matched_rows.csv")
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title Label
        title_label = ttk.Label(main_frame, text="CSV LinkedIn URL Matcher", 
                               font=('Helvetica', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # License status label
        self.license_label = ttk.Label(main_frame, text="", font=('Helvetica', 9), foreground="green")
        self.license_label.grid(row=1, column=0, columnspan=3, pady=(0, 10))
        self.update_license_status()
        
        # Main File Selection
        ttk.Label(main_frame, text="Main CSV File:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.main_file_path, width=40).grid(row=2, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_main_file).grid(row=2, column=2, pady=5)
        
        # New Table File Selection
        ttk.Label(main_frame, text="New Table CSV:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.new_table_path, width=40).grid(row=3, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_new_table).grid(row=3, column=2, pady=5)
        
        # Output File
        ttk.Label(main_frame, text="Output File:").grid(row=4, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.output_path, width=40).grid(row=4, column=1, padx=5, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=4, column=2, pady=5)
        
        # Process Button
        self.process_btn = ttk.Button(main_frame, text="Match URLs", command=self.process_files, 
                                     style="Accent.TButton")
        self.process_btn.grid(row=5, column=0, columnspan=3, pady=20)
        
        # Progress Bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status Text Area
        ttk.Label(main_frame, text="Status:").grid(row=7, column=0, sticky=tk.W, pady=5)
        
        # Create frame for text widget and scrollbar
        text_frame = ttk.Frame(main_frame)
        text_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Status text with scrollbar
        self.status_text = tk.Text(text_frame, height=8, width=70, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.status_text.yview)
        self.status_text.configure(yscrollcommand=scrollbar.set)
        
        self.status_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure text frame grid weights
        text_frame.columnconfigure(0, weight=1)
        text_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(8, weight=1)
        
        # Menu bar
        menubar = tk.Menu(root)
        root.config(menu=menubar)
        
        # License menu
        license_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="License", menu=license_menu)
        license_menu.add_command(label="View License Status", command=self.show_license_status)
        license_menu.add_command(label="Change License Key", command=self.change_license)
        
        # Style configuration
        style = ttk.Style()
        style.configure("Accent.TButton", font=('Helvetica', 10, 'bold'))
        
        self.log_message("Ready to process CSV files...")
    
    def check_license(self):
        """Check if valid license exists"""
        # Try to load existing license
        saved_key = self.license_manager.load_license()
        
        if saved_key:
            is_valid, message = self.license_manager.validate_license(saved_key)
            if is_valid:
                return True
        
        # Show license dialog
        dialog = LicenseDialog(self.root, self.license_manager)
        self.root.wait_window(dialog.dialog)
        
        return dialog.result
    
    def update_license_status(self):
        """Update license status display"""
        saved_key = self.license_manager.load_license()
        if saved_key:
            is_valid, message = self.license_manager.validate_license(saved_key)
            if is_valid:
                self.license_label.config(text=f"✓ {message}", foreground="green")
            else:
                self.license_label.config(text=f"✗ {message}", foreground="red")
    
    def show_license_status(self):
        """Show detailed license status"""
        saved_key = self.license_manager.load_license()
        if saved_key:
            is_valid, message = self.license_manager.validate_license(saved_key)
            if is_valid:
                messagebox.showinfo("License Status", f"License Status: Active\n\n{message}")
            else:
                messagebox.showwarning("License Status", f"License Status: Invalid\n\n{message}")
        else:
            messagebox.showwarning("License Status", "No license key found")
    
    def change_license(self):
        """Change license key"""
        dialog = LicenseDialog(self.root, self.license_manager)
        self.root.wait_window(dialog.dialog)
        if dialog.result:
            self.update_license_status()
    
    def log_message(self, message):
        """Add message to status text area"""
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END)
        self.root.update_idletasks()
    
    def browse_main_file(self):
        filename = filedialog.askopenfilename(
            title="Select Main CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.main_file_path.set(filename)
            self.log_message(f"Selected main file: {os.path.basename(filename)}")
    
    def browse_new_table(self):
        filename = filedialog.askopenfilename(
            title="Select New Table CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.new_table_path.set(filename)
            self.log_message(f"Selected new table file: {os.path.basename(filename)}")
    
    def browse_output(self):
        filename = filedialog.asksaveasfilename(
            title="Save Output As",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            self.output_path.set(filename)
            self.log_message(f"Output will be saved as: {os.path.basename(filename)}")
    
    def process_files(self):
        """Process the CSV files in a separate thread"""
        # Check license before processing
        saved_key = self.license_manager.load_license()
        if saved_key:
            is_valid, message = self.license_manager.validate_license(saved_key)
            if not is_valid:
                messagebox.showerror("License Error", f"Cannot process files:\n{message}")
                return
        
        thread = Thread(target=self._process_files_thread)
        thread.daemon = True
        thread.start()
    
    def _process_files_thread(self):
        """Thread function to process files without freezing GUI"""
        try:
            # Disable process button and start progress bar
            self.process_btn.config(state='disabled')
            self.progress.start(10)
            
            # Validate inputs
            if not self.main_file_path.get():
                raise ValueError("Please select the main CSV file")
            
            if not self.new_table_path.get():
                raise ValueError("Please select the new table CSV file")
            
            if not self.output_path.get():
                raise ValueError("Please specify an output file name")
            
            # Check if files exist
            if not os.path.exists(self.main_file_path.get()):
                raise FileNotFoundError(f"Main file not found: {self.main_file_path.get()}")
            
            if not os.path.exists(self.new_table_path.get()):
                raise FileNotFoundError(f"New table file not found: {self.new_table_path.get()}")
            
            self.log_message("\nStarting to process files...")
            
            # Read CSV files
            self.log_message("Reading main CSV file...")
            main_df = pd.read_csv(self.main_file_path.get())
            self.log_message(f"Main file loaded: {len(main_df)} rows")
            
            self.log_message("Reading new table CSV file...")
            new_table_df = pd.read_csv(self.new_table_path.get())
            self.log_message(f"New table loaded: {len(new_table_df)} rows")
            
            # Check if required columns exist
            if 'Person Linkedin Url' not in main_df.columns:
                raise KeyError("Column 'Person Linkedin Url' not found in main file")
            
            if 'linkedin_url' not in new_table_df.columns:
                raise KeyError("Column 'linkedin_url' not found in new table file")
            
            # Perform matching
            self.log_message("Matching LinkedIn URLs...")
            matched_rows = main_df[main_df['Person Linkedin Url'].isin(new_table_df['linkedin_url'])]
            
            # Save results
            self.log_message(f"Found {len(matched_rows)} matching rows")
            self.log_message(f"Saving to {self.output_path.get()}...")
            matched_rows.to_csv(self.output_path.get(), index=False)
            
            # Success message
            self.log_message(f"\n✅ Success! Matched rows saved to '{self.output_path.get()}'")
            self.log_message(f"Total matched rows: {len(matched_rows)}")
            
            messagebox.showinfo("Success", 
                              f"Processing complete!\n\n"
                              f"Matched {len(matched_rows)} rows\n"
                              f"Saved to: {self.output_path.get()}")
            
        except Exception as e:
            error_msg = f"❌ Error: {str(e)}"
            self.log_message(error_msg)
            messagebox.showerror("Error", str(e))
        
        finally:
            # Stop progress bar and re-enable button
            self.progress.stop()
            self.process_btn.config(state='normal')

def main():
    # Check for required packages
    try:
        import cryptography
    except ImportError:
        print("Please install required packages:")
        print("pip install cryptography pandas")
        sys.exit(1)
    
    root = tk.Tk()
    app = CSVMatcherGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
