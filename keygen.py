import tkinter as tk
from tkinter import ttk, messagebox
import json
import hashlib
from datetime import datetime, timedelta
import base64
import platform
import socket

class KeyGenerator:
    def __init__(self):
        self.secret = b"NADERMAHBUBKHAN34322$$$$$433n6463642"  # Must match main app exactly
        self.secret_key = self._get_fernet_key()
        
    def _get_fernet_key(self):
        """Generate Fernet key from secret - MUST match main.py exactly"""
        return base64.urlsafe_b64encode(hashlib.sha256(self.secret).digest())
    
    def encrypt_decrypt(self, text, key):
        """Simple XOR encryption/decryption - MUST match main.py exactly"""
        result = ''
        key = key.decode() if isinstance(key, bytes) else key
        for i, char in enumerate(text):
            result += chr(ord(char) ^ ord(key[i % len(key)]))
        return result
    
    def generate_key(self, time_value=30, time_unit='days', machine_bound=False, user_name="User", notes=""):
        """Generate a license key with flexible time units"""
        try:
            # Calculate expiry date based on time unit
            if time_unit == 'minutes':
                expiry_date = datetime.now() + timedelta(minutes=time_value)
            elif time_unit == 'hours':
                expiry_date = datetime.now() + timedelta(hours=time_value)
            elif time_unit == 'days':
                expiry_date = datetime.now() + timedelta(days=time_value)
            elif time_unit == 'weeks':
                expiry_date = datetime.now() + timedelta(weeks=time_value)
            elif time_unit == 'months':
                expiry_date = datetime.now() + timedelta(days=time_value * 30)  # Approximate
            elif time_unit == 'years':
                expiry_date = datetime.now() + timedelta(days=time_value * 365)
            else:
                raise ValueError(f"Invalid time unit: {time_unit}")
            
            # Create license data
            license_data = {
                'valid': True,
                'created_date': datetime.now().isoformat(),
                'expiry_date': expiry_date.isoformat(),
                'user_name': user_name,
                'notes': notes,
                'time_value': time_value,
                'time_unit': time_unit,
                'license_type': self._get_license_type(time_value, time_unit)
            }
            
            # Add machine binding if requested
            if machine_bound:
                license_data['machine_id'] = self._get_machine_id()
            else:
                license_data['machine_id'] = None
            
            # Create checksum - MUST match main.py format
            data_str = f"{license_data['user_name']}{license_data['expiry_date']}{license_data['valid']}"
            license_data['checksum'] = hashlib.md5(data_str.encode()).hexdigest()
            
            # Convert to JSON
            json_data = json.dumps(license_data)
            
            # Encrypt using the same method as main.py
            encrypted = self.encrypt_decrypt(json_data, self.secret_key)
            
            # Encode to base64
            encoded = base64.b64encode(encrypted.encode()).decode()
            
            return encoded, license_data
            
        except Exception as e:
            raise Exception(f"Failed to generate key: {str(e)}")
    
    def _get_license_type(self, time_value, time_unit):
        """Determine license type based on duration"""
        if time_unit == 'minutes':
            if time_value <= 60:
                return "Trial (Minutes)"
            else:
                return "Short Trial"
        elif time_unit == 'hours':
            if time_value <= 24:
                return "Trial (Hours)"
            else:
                return "Extended Trial"
        elif time_unit == 'days':
            if time_value <= 7:
                return "Weekly Trial"
            elif time_value <= 30:
                return "Monthly License"
            elif time_value <= 365:
                return "Annual License"
            else:
                return "Lifetime License"
        return "Standard License"
    
    def _get_machine_id(self):
        """Get unique machine identifier - MUST match main.py"""
        try:
            hostname = socket.gethostname()
            platform_info = platform.platform()
            machine_string = f"{hostname}-{platform_info}"
            return hashlib.sha256(machine_string.encode()).hexdigest()[:16]
        except:
            return "default"

class KeyGenGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced License Key Generator")
        self.root.geometry("700x750")
        self.root.resizable(False, False)
        
        self.key_gen = KeyGenerator()
        
        # Main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="CSV Matcher License Generator", 
                               font=('Helvetica', 16, 'bold'))
        title_label.pack(pady=(0, 20))
        
        # Input fields frame
        input_frame = ttk.LabelFrame(main_frame, text="License Details", padding="10")
        input_frame.pack(fill=tk.X, pady=(0, 20))
        
        # User name
        ttk.Label(input_frame, text="User Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.user_name = tk.StringVar(value="User")
        ttk.Entry(input_frame, textvariable=self.user_name, width=40).grid(row=0, column=1, columnspan=2, pady=5, padx=(10, 0))
        
        # Time-based validity
        ttk.Label(input_frame, text="Valid for:").grid(row=1, column=0, sticky=tk.W, pady=5)
        
        # Time value and unit frame
        time_frame = ttk.Frame(input_frame)
        time_frame.grid(row=1, column=1, columnspan=2, pady=5, padx=(10, 0), sticky=tk.W)
        
        self.time_value = tk.IntVar(value=30)
        time_spinbox = ttk.Spinbox(time_frame, from_=1, to=9999, textvariable=self.time_value, width=10)
        time_spinbox.pack(side=tk.LEFT)
        
        self.time_unit = tk.StringVar(value="days")
        time_unit_combo = ttk.Combobox(time_frame, textvariable=self.time_unit, 
                                       values=["minutes", "hours", "days", "weeks", "months", "years"],
                                       width=10, state="readonly")
        time_unit_combo.pack(side=tk.LEFT, padx=(5, 0))
        
        # Quick select buttons frame
        quick_frame = ttk.LabelFrame(input_frame, text="Quick Select", padding="5")
        quick_frame.grid(row=2, column=0, columnspan=3, pady=10, sticky=(tk.W, tk.E))
        
        # Trial licenses (minutes/hours)
        trial_frame = ttk.Frame(quick_frame)
        trial_frame.pack(fill=tk.X, pady=2)
        ttk.Label(trial_frame, text="Trials:", width=10).pack(side=tk.LEFT)
        ttk.Button(trial_frame, text="15 min", width=8,
                  command=lambda: self.set_time(15, "minutes")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="30 min", width=8,
                  command=lambda: self.set_time(30, "minutes")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="1 hour", width=8,
                  command=lambda: self.set_time(1, "hours")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="3 hours", width=8,
                  command=lambda: self.set_time(3, "hours")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="6 hours", width=8,
                  command=lambda: self.set_time(6, "hours")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="12 hours", width=8,
                  command=lambda: self.set_time(12, "hours")).pack(side=tk.LEFT, padx=2)
        ttk.Button(trial_frame, text="24 hours", width=8,
                  command=lambda: self.set_time(24, "hours")).pack(side=tk.LEFT, padx=2)
        
        # Standard licenses (days)
        standard_frame = ttk.Frame(quick_frame)
        standard_frame.pack(fill=tk.X, pady=2)
        ttk.Label(standard_frame, text="Standard:", width=10).pack(side=tk.LEFT)
        ttk.Button(standard_frame, text="1 day", width=8,
                  command=lambda: self.set_time(1, "days")).pack(side=tk.LEFT, padx=2)
        ttk.Button(standard_frame, text="3 days", width=8,
                  command=lambda: self.set_time(3, "days")).pack(side=tk.LEFT, padx=2)
        ttk.Button(standard_frame, text="7 days", width=8,
                  command=lambda: self.set_time(7, "days")).pack(side=tk.LEFT, padx=2)
        ttk.Button(standard_frame, text="14 days", width=8,
                  command=lambda: self.set_time(14, "days")).pack(side=tk.LEFT, padx=2)
        ttk.Button(standard_frame, text="30 days", width=8,
                  command=lambda: self.set_time(30, "days")).pack(side=tk.LEFT, padx=2)
        ttk.Button(standard_frame, text="90 days", width=8,
                  command=lambda: self.set_time(90, "days")).pack(side=tk.LEFT, padx=2)
        
        # Extended licenses
        extended_frame = ttk.Frame(quick_frame)
        extended_frame.pack(fill=tk.X, pady=2)
        ttk.Label(extended_frame, text="Extended:", width=10).pack(side=tk.LEFT)
        ttk.Button(extended_frame, text="6 months", width=8,
                  command=lambda: self.set_time(6, "months")).pack(side=tk.LEFT, padx=2)
        ttk.Button(extended_frame, text="1 year", width=8,
                  command=lambda: self.set_time(1, "years")).pack(side=tk.LEFT, padx=2)
        ttk.Button(extended_frame, text="2 years", width=8,
                  command=lambda: self.set_time(2, "years")).pack(side=tk.LEFT, padx=2)
        ttk.Button(extended_frame, text="Lifetime", width=8,
                  command=lambda: self.set_time(10, "years")).pack(side=tk.LEFT, padx=2)
        
        # Machine binding
        ttk.Label(input_frame, text="Machine Binding:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.machine_bound = tk.BooleanVar(value=False)
        machine_check = ttk.Checkbutton(input_frame, text="Bind to current machine", 
                                       variable=self.machine_bound)
        machine_check.grid(row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Notes
        ttk.Label(input_frame, text="Notes:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.notes = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.notes, width=40).grid(row=4, column=1, columnspan=2, pady=5, padx=(10, 0))
        
        # Generate button
        generate_btn = ttk.Button(main_frame, text="Generate License Key", 
                                 command=self.generate_key, style="Accent.TButton")
        generate_btn.pack(pady=10)
        
        # Key display frame
        key_frame = ttk.LabelFrame(main_frame, text="Generated License Key", padding="10")
        key_frame.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        
        # Key text area
        self.key_text = tk.Text(key_frame, height=6, width=75, wrap=tk.WORD)
        self.key_text.pack(pady=(0, 10))
        
        # Copy button
        self.copy_btn = ttk.Button(key_frame, text="Copy to Clipboard", 
                                   command=self.copy_key, state='disabled')
        self.copy_btn.pack()
        
        # Info display
        self.info_frame = ttk.LabelFrame(main_frame, text="License Information", padding="10")
        self.info_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.info_text = tk.Text(self.info_frame, height=7, width=75, wrap=tk.WORD, state='disabled')
        self.info_text.pack()
        
        # Style
        style = ttk.Style()
        style.configure("Accent.TButton", font=('Helvetica', 10, 'bold'))
    
    def set_time(self, value, unit):
        """Set time value and unit from quick select buttons"""
        self.time_value.set(value)
        self.time_unit.set(unit)
    
    def format_duration(self, time_value, time_unit):
        """Format duration for display"""
        if time_unit == 'minutes':
            if time_value == 1:
                return "1 minute"
            else:
                return f"{time_value} minutes"
        elif time_unit == 'hours':
            if time_value == 1:
                return "1 hour"
            else:
                return f"{time_value} hours"
        elif time_unit == 'days':
            if time_value == 1:
                return "1 day"
            else:
                return f"{time_value} days"
        elif time_unit == 'weeks':
            if time_value == 1:
                return "1 week"
            else:
                return f"{time_value} weeks"
        elif time_unit == 'months':
            if time_value == 1:
                return "1 month"
            else:
                return f"{time_value} months"
        elif time_unit == 'years':
            if time_value == 1:
                return "1 year"
            elif time_value >= 10:
                return "Lifetime"
            else:
                return f"{time_value} years"
        return f"{time_value} {time_unit}"
    
    def generate_key(self):
        """Generate a new license key"""
        try:
            user_name = self.user_name.get().strip()
            if not user_name:
                messagebox.showerror("Error", "Please enter a user name")
                return
            
            time_value = self.time_value.get()
            time_unit = self.time_unit.get()
            machine_bound = self.machine_bound.get()
            notes = self.notes.get().strip()
            
            # Generate the key
            key_string, license_data = self.key_gen.generate_key(
                time_value=time_value,
                time_unit=time_unit,
                machine_bound=machine_bound,
                user_name=user_name,
                notes=notes
            )
            
            # Display the key
            self.key_text.delete(1.0, tk.END)
            self.key_text.insert(1.0, key_string)
            
            # Enable copy button
            self.copy_btn.config(state='normal')
            
            # Display license info
            self.info_text.config(state='normal')
            self.info_text.delete(1.0, tk.END)
            
            created_date = datetime.fromisoformat(license_data['created_date'])
            expiry_date = datetime.fromisoformat(license_data['expiry_date'])
            
            # Calculate exact duration
            duration = expiry_date - created_date
            total_seconds = int(duration.total_seconds())
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            minutes = (total_seconds % 3600) // 60
            
            duration_str = self.format_duration(time_value, time_unit)
            
            # Format exact duration display
            if days > 0:
                exact_duration = f"{days} days, {hours} hours, {minutes} minutes"
            elif hours > 0:
                exact_duration = f"{hours} hours, {minutes} minutes"
            else:
                exact_duration = f"{minutes} minutes"
            
            info_lines = [
                f"User: {license_data['user_name']}",
                f"License Type: {license_data['license_type']}",
                f"Created: {created_date.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Expires: {expiry_date.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Duration: {duration_str} (exactly: {exact_duration})",
                f"Machine Bound: {'Yes - ' + license_data['machine_id'][:8] + '...' if license_data['machine_id'] else 'No'}",
            ]
            if license_data.get('notes'):
                info_lines.append(f"Notes: {license_data['notes']}")
            
            self.info_text.insert(1.0, '\n'.join(info_lines))
            self.info_text.config(state='disabled')
            
            messagebox.showinfo("Success", f"License key generated successfully!\n\nDuration: {duration_str}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate key: {str(e)}")
    
    def copy_key(self):
        """Copy the generated key to clipboard"""
        key_string = self.key_text.get(1.0, tk.END).strip()
        if key_string:
            self.root.clipboard_clear()
            self.root.clipboard_append(key_string)
            self.root.update()
            messagebox.showinfo("Success", "License key copied to clipboard!")

def main():
    root = tk.Tk()
    app = KeyGenGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()