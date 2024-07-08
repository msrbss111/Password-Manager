# Importing tkinter for the GUI
import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, Listbox, SINGLE

# Importing json to store the password in json format
import json

# Importing os to traverse the directory
import os

# Importing base64 to encode and decode the password
import base64

# Importing random and string to generate passswords
import random
import string

# Importing hashlib to hash the master key
import hashlib

# Importing crytography to encrypt the credentials
from cryptography.fernet import Fernet, InvalidToken



# This function is to whether the Master key entered is in the correct format
def check_master_key_policy(MASTER_KEY):
    if len(MASTER_KEY) < 14:
        return False
    if not any(capital.isupper() for capital in MASTER_KEY):
        return False
    if not any(digit.isdigit() for digit in MASTER_KEY):
        return False
    if not any(special_c in string.punctuation for special_c in MASTER_KEY):
        return False
    else:
        return True


# This function is used to load the master key stored in the hash format
def loading_the_hashed_master_key():
    master_key_file = os.path.join(os.path.expanduser("~"), "MASTER_KEY.hash")
    if os.path.exists(master_key_file):
        with open(master_key_file, "r") as MK:
            MASTER_KEY_HASH = MK.read()
    else:
        MASTER_KEY_HASH = None
    return MASTER_KEY_HASH


# This function is used to save the hash of the master key
def saving_the_hashed_master_key(MASTER_KEY):
    master_key_file = os.path.join(os.path.expanduser("~"), "MASTER_KEY.hash")
    MASTER_KEY_HASH = hashlib.sha256(MASTER_KEY.encode()).hexdigest()
    with open(master_key_file, "w") as mkf:
        mkf.write(MASTER_KEY_HASH)


# This function is used to verify master key against the hashed master key
def verifying_the_master_key_with_the_hashed_master_key(USER_INPUT_KEY):
    STORED_MASTER_KEY_HASH = loading_the_hashed_master_key()
    USER_INPUT_KEY_HASH = hashlib.sha256(USER_INPUT_KEY.encode()).hexdigest()
    return USER_INPUT_KEY_HASH == STORED_MASTER_KEY_HASH


# This function is used to encode the master key and perform a symmetric encryption 
# to encrypt the encoded master key
def performing_encoding_and_encryption(MASTER_KEY):
    HASHED_MASTER_KEY = hashlib.sha256(MASTER_KEY.encode()).digest()[:32]
    return Fernet(base64.urlsafe_b64encode(HASHED_MASTER_KEY))


# This function is used to encrypt the data and return the decrypted and decoded the data
def encrypting_the_data(data, CIPHER_SUITE):
    ENCODED_DATA = data.encode()
    ENCRYPTED_DATA = CIPHER_SUITE.encrypt(ENCODED_DATA)
    return base64.b64encode(ENCRYPTED_DATA).decode()


# This function is used to decrypt the data
def decrypting_the_data(ENCODED_ENCRYPTED_DATA, CIPHER_SUITE):
    try:
        ENCRYPTED_DATA = base64.b64decode(ENCODED_ENCRYPTED_DATA)
        DECRYPTED_DATA = CIPHER_SUITE.decrypt(ENCRYPTED_DATA).decode()
        return DECRYPTED_DATA
    except (ValueError, InvalidToken) as e:
        print(f"Error Occured when decrypting the data: {e}")
        return "Error in Decryption"
    

# This function is used to save all the credentials into a JSON file
def saving_all_the_credentials(CREDENTIALS):
    with open("CREDENTIALS.json", "w") as cds:
        json.dump(CREDENTIALS, cds, indent=4)



# This is the function to load all the credentials from the JSON file
def loading_all_the_credentials():
    if os.path.exists("CREDENTIALS.json"):
        with open("CREDENTIALS.json", "r") as cds:
            try:
                CREDENTIALS = json.load(cds)
            except json.JSONDecodeError:
                CREDENTIALS = {}
    else:
        CREDENTIALS = {}
    return CREDENTIALS



# This the function to generate a random password for the username of an application
def generating_a_random_password():
    CHARACTERS = string.ascii_letters + string.digits + string.punctuation
    PASSWORD = ''.join(random.choice(CHARACTERS) for i in range(random.randint(15, 20)))
    return PASSWORD



# This function is used to set the master key or change master key
def setting_the_master_key():
    if loading_the_hashed_master_key() is not None:
        messagebox.showinfo("Infomation", "The Master key has already been set.")
    else:
        while True:
            MASTER_KEY = simpledialog.askstring("Setting up the Master Key", "Please enter a strong Master Key of 14 characters or more that includes a captital letter, a number and a special character, Enter the Master Key:", show='*')
            if MASTER_KEY:
                if check_master_key_policy(MASTER_KEY):
                    saving_the_hashed_master_key(MASTER_KEY)
                    messagebox.showinfo("Successful", "The Master key has been set.")
                    break
                else:
                    messagebox.showerror("Invalid Master Key", "Please enter a strong Master Key of 14 characters or more that includes a captital letter, a number and a special character, Enter the Master Key:")
            else:
                messagebox.showerror("Error Occurred", "Text Field is empty, Please Enter the Master Key")
                break




# This function is to replace or change the master key
def changing_the_master_key():
    CURRENT_MASTER_KEY = simpledialog.askstring("Current Master Key", "Enter the Current Master Key : ", show='*')
    if not CURRENT_MASTER_KEY:
        return
    if not verifying_the_master_key_with_the_hashed_master_key(CURRENT_MASTER_KEY):
        messagebox.showerror("Error Occured", "The Master Key entered is Invalid. Access Denied!")
        return
    
    while True:
        NEW_MASTER_KEY = simpledialog.askstring("New Master Key", "Enter the New Master Key : ", show='*')
        if not NEW_MASTER_KEY:
            return
        
        if check_master_key_policy(NEW_MASTER_KEY):
            current_encoding_and_encryption = performing_encoding_and_encryption(CURRENT_MASTER_KEY)
            new_encoding_and_encryption = performing_encoding_and_encryption(NEW_MASTER_KEY)

            CREDENTIALS = loading_all_the_credentials()
            CREDENTIALS_DECRYPTED = {}

            try:
                for APPLICATION_ENCRYPTED, CREDENTIAL_DETAILS in CREDENTIALS.items():
                    APPLICATION_DECRYPTED = decrypting_the_data(APPLICATION_ENCRYPTED, current_encoding_and_encryption)
                    USERNAME_DECRYPTED = decrypting_the_data(CREDENTIAL_DETAILS['Username'], current_encoding_and_encryption)
                    PASSWORD_DECRYPTED = decrypting_the_data(CREDENTIAL_DETAILS['Password'], current_encoding_and_encryption)

                    if "Error in Decryption" in [APPLICATION_DECRYPTED, USERNAME_DECRYPTED, PASSWORD_DECRYPTED]:
                        messagebox.showerror("Error Occurred", "Failed to decrypt the credential data with the current master key.")
                        return

                    NEW_ENCRYPTED_APPLICATION = encrypting_the_data(APPLICATION_DECRYPTED, new_encoding_and_encryption)
                    NEW_ENCRYPTED_USERNAME = encrypting_the_data(USERNAME_DECRYPTED, new_encoding_and_encryption)
                    NEW_ENCRYPTED_PASSWORD = encrypting_the_data(PASSWORD_DECRYPTED, new_encoding_and_encryption)
                    CREDENTIALS_DECRYPTED[NEW_ENCRYPTED_APPLICATION] = {"Username": NEW_ENCRYPTED_USERNAME, "Password": NEW_ENCRYPTED_PASSWORD}

                saving_all_the_credentials(CREDENTIALS_DECRYPTED)
                saving_the_hashed_master_key(NEW_MASTER_KEY)
                messagebox.showinfo("Successful", "The Master key has been changed and the credentials are re-encrypted.")
                break

            except InvalidToken:
                messagebox.showerror("Error Occurred", "The Master Key entered is Invalid. Access Denied!")
        
        else:
            messagebox.showerror("Invalid Master Key", "Please enter a strong Master Key of 14 characters or more that includes a captital letter, a number and a special character, Enter the Master Key:" )


# Function to clear all input fields
def clear_all_the_fields():
    Application_entry.delete(0, tk.END)
    Username_entry.delete(0, tk.END)
    Password_entry.delete(0, tk.END)




# This function is to add a new credential
def add_a_credential():
    HASHED_MASTER_KEY = loading_the_hashed_master_key()
    if HASHED_MASTER_KEY is None:
        messagebox.showerror("Error Occurred", "The Master Key is not set. Please set the master key.")
        return


    MASTER_KEY = simpledialog.askstring("MASTER KEY", "Please enter the Master Key:", show='*')
    if not MASTER_KEY:
        messagebox.showerror("Error Occurred", "Text Field is empty, Please enter the Master Key")
        add_a_credential()
        # return
    if not verifying_the_master_key_with_the_hashed_master_key(MASTER_KEY):
        messagebox.showerror("Error Occurred", "The Master Key entered is Invalid. Access Denied!")
        return
    encoding_and_encryption = performing_encoding_and_encryption(MASTER_KEY)

    Application = Application_entry.get()
    Username = Username_entry.get()
    Password = Password_entry.get()

    if Application.strip() == "" or Username.strip() == "" or Password.strip() == "":
        messagebox.showerror("Error Occured", "Text Fields are Empty, Please enter the Application Name, Username, and Password")
        return



    APPLICATION_ENCRYPTED = encrypting_the_data(Application, encoding_and_encryption)

    USERNAME_ENCRYPTED = encrypting_the_data(Username, encoding_and_encryption)

    Application_Username = Application + " -------- "+ Username
    APPLICATION_ENCRYPTED = encrypting_the_data(Application_Username, encoding_and_encryption)
    
    PASSWORD_ENCRYPTED = encrypting_the_data(Password, encoding_and_encryption)



    CREDENTIALS = loading_all_the_credentials()
    CREDENTIALS[APPLICATION_ENCRYPTED] = {"Username": USERNAME_ENCRYPTED, "Password": PASSWORD_ENCRYPTED}
    saving_all_the_credentials(CREDENTIALS)
    messagebox.showinfo("Successful", "Credential is saved successfully")
    clear_all_the_fields()




# Function to view all passwords
def view_all_the_credentials():
    MASTER_KEY = simpledialog.askstring("MASTER KEY", "Please enter the Master Key:", show='*')
    if not MASTER_KEY:
        messagebox.showerror("Error Occurred", "The Master Key is not set. Please set the master key.")
        return
    if not verifying_the_master_key_with_the_hashed_master_key(MASTER_KEY):
        messagebox.showerror("Error Occurred", "The Master Key entered is Invalid. Access Denied!")
        return
    encoding_and_encryption = performing_encoding_and_encryption(MASTER_KEY)

    try:
        CREDENTIALS_DECRYPTED = {}
        CREDENTIALS = loading_all_the_credentials()
        ENCRYPTING_TO_DECRYPTING = {}

        for APPLICATION_ENCRYPTED, CREDENTIAL_DETAILS in CREDENTIALS.items():
            APPLICATION_DECRYPTED = decrypting_the_data(APPLICATION_ENCRYPTED, encoding_and_encryption)
            USERNAME_DECRYPTED = decrypting_the_data(CREDENTIAL_DETAILS['Username'], encoding_and_encryption)
            PASSWORD_DECRYPTED = decrypting_the_data(CREDENTIAL_DETAILS['Password'], encoding_and_encryption)
            CREDENTIALS_DECRYPTED[APPLICATION_DECRYPTED] = {"Username": USERNAME_DECRYPTED, "Password": PASSWORD_DECRYPTED}
            ENCRYPTING_TO_DECRYPTING[APPLICATION_DECRYPTED] = APPLICATION_ENCRYPTED

        WINDOW_CREDENTIALS = tk.Toplevel(PMT)
        WINDOW_CREDENTIALS.title("CREDENTIALS STORED")
        WINDOW_CREDENTIALS.geometry("400x450")

        LISTBOX = Listbox(WINDOW_CREDENTIALS, selectmode = SINGLE, width = 50, height = 10)
        LISTBOX.pack(padx = 10, pady = 10)

        for APPLICATION in CREDENTIALS_DECRYPTED:
            LISTBOX.insert(tk.END, APPLICATION)

        credential_scrolled_text = scrolledtext.ScrolledText(WINDOW_CREDENTIALS, width = 40, height = 10)
        credential_scrolled_text.pack(padx = 10, pady = 10)

        def displaying_the_credential(event):
            chosen_application = LISTBOX.get(LISTBOX.curselection())
            if chosen_application:
                CREDENTIAL_DETAILS = CREDENTIALS_DECRYPTED[chosen_application]
                credential_scrolled_text.config(state=tk.NORMAL)
                credential_scrolled_text.delete(1.0, tk.END)
                credential_scrolled_text.insert(tk.END, f"Application Name: {chosen_application}\nUsername: {CREDENTIAL_DETAILS['Username']}\nPassword: {CREDENTIAL_DETAILS['Password']}\n")
                credential_scrolled_text.config(state=tk.DISABLED)


        def refreshing_the_credentials_page():
            LISTBOX.delete(0, tk.END)
            for application in CREDENTIALS_DECRYPTED:
                LISTBOX.insert(tk.END, application)
            credential_scrolled_text.config(state=tk.NORMAL)
            credential_scrolled_text.delete(1.0, tk.END)
            credential_scrolled_text.config(state=tk.DISABLED)


        def deleting_the_credentials():
            chosen_application = LISTBOX.get(LISTBOX.curselection())
            if chosen_application in CREDENTIALS_DECRYPTED:
                APPLICATION_ENCRYPTED = ENCRYPTING_TO_DECRYPTING[chosen_application]
                del CREDENTIALS[APPLICATION_ENCRYPTED]
                saving_all_the_credentials(CREDENTIALS)
                messagebox.showinfo("Successful", f"The credential for {chosen_application} is deleted successfully")
                CREDENTIALS_DECRYPTED.pop(chosen_application, None)
                refreshing_the_credentials_page()
            else:
                messagebox.showerror("Error Occurred", f"No credential found for {chosen_application}")


        def updating_the_credentials():
            chosen_application = LISTBOX.get(LISTBOX.curselection())
            if chosen_application in CREDENTIALS_DECRYPTED:
                update_window = tk.Toplevel(PMT)
                update_window.title("Updating Credential")
                update_window.geometry("300x300")

                new_application_name_label = tk.Label(update_window, text="New Application Name : ")
                new_application_name_label.pack(pady=5)
                new_application_name_entry = tk.Entry(update_window, width=30)
                new_application_name_entry.pack()

                new_username_label = tk.Label(update_window, text="New Username : ")
                new_username_label.pack(pady=5)
                new_username_entry = tk.Entry(update_window, width=30)
                new_username_entry.pack()

                new_password_label = tk.Label(update_window, text="New Password : ")
                new_password_label.pack(pady=5)
                new_password_entry = tk.Entry(update_window, width=30, show="*")
                new_password_entry.pack()

                def generate_password_for_update():
                    new_password_entry.delete(0, tk.END)
                    new_password_entry.insert(tk.END, generating_a_random_password())

                UPDATE_GENERATE_PASSWORD_BUTTON = tk.Button(update_window, text="GENERATE PASSWORD", command=generate_password_for_update)
                UPDATE_GENERATE_PASSWORD_BUTTON.pack(pady=10)

                def save_updated_credential():
                    NEW_APPLICATION_NAME = new_application_name_entry.get()
                    NEW_USERNAME = new_username_entry.get()
                    NEW_PASSWORD = new_password_entry.get()

                    if NEW_USERNAME.strip() != "" and NEW_PASSWORD.strip() != "" and NEW_APPLICATION_NAME.strip() != "":
                        # Encrypt new application name with username and store as application
                        NEW_APPLICATION_NAME_USERNAME = NEW_APPLICATION_NAME + " -------- " + NEW_USERNAME
                        NEW_APPLICATION_ENCRYPTED = encrypting_the_data(NEW_APPLICATION_NAME_USERNAME, encoding_and_encryption)

                        # Encrypt the new username
                        NEW_USERNAME_ENCRYPTED = encrypting_the_data(NEW_USERNAME, encoding_and_encryption)

                        # Encrypt the new password
                        NEW_PASSWORD_ENCRYPTED = encrypting_the_data(NEW_PASSWORD, encoding_and_encryption)

                        # Remove previous entry
                        PREVIOUS_APPLICATION_ENCRYPTED = ENCRYPTING_TO_DECRYPTING[chosen_application]
                        del CREDENTIALS[PREVIOUS_APPLICATION_ENCRYPTED]

                        # Add new entry
                        CREDENTIALS[NEW_APPLICATION_ENCRYPTED] = {"Username": NEW_USERNAME_ENCRYPTED, "Password": NEW_PASSWORD_ENCRYPTED}

                        # Update credentials dictionaries
                        ENCRYPTING_TO_DECRYPTING.pop(chosen_application)
                        CREDENTIALS_DECRYPTED.pop(chosen_application)

                        ENCRYPTING_TO_DECRYPTING[NEW_APPLICATION_NAME_USERNAME] = NEW_APPLICATION_ENCRYPTED
                        CREDENTIALS_DECRYPTED[NEW_APPLICATION_NAME_USERNAME] = {"Username": NEW_USERNAME, "Password": NEW_PASSWORD}

                        # Save updated credentials
                        saving_all_the_credentials(CREDENTIALS)

                        messagebox.showinfo("Successful", f"The credential for {NEW_APPLICATION_NAME_USERNAME} has been updated successfully")
                        refreshing_the_credentials_page()
                        update_window.destroy()
                    else:
                        messagebox.showerror("Error Occurred", "All fields are required to update the credential")

                SAVE_UPDATED_CREDENTIAL_BUTTON = tk.Button(update_window, text=" UPDATE & SAVE CREDENTIAL", command=save_updated_credential)
                SAVE_UPDATED_CREDENTIAL_BUTTON.pack(pady=10)


            else:
                messagebox.showerror("Error Occurred", f"No credential found for {chosen_application}")


        LISTBOX.bind("<<ListboxSelect>>", displaying_the_credential)

        BUTTON_TO_DELETE = tk.Button(WINDOW_CREDENTIALS, text="DELETE CREDENTIAL", command=deleting_the_credentials)
        BUTTON_TO_DELETE.pack(pady=5)

        BUTTON_TO_UPDATE = tk.Button(WINDOW_CREDENTIALS, text="UPDATE CREDENTIAL", command=updating_the_credentials)
        BUTTON_TO_UPDATE.pack(pady=5)

    except InvalidToken:
        messagebox.showerror("Error Occurred", "The Master Key entered is Invalid. Access Denied!")



# Initializing and setting up the tkinter GUI
PMT = tk.Tk()
PMT.title("PassGuard - Password Manager Tool")
PMT.geometry("370x450")

# Creating the GUI elements
Application_label = tk.Label(PMT, text="Application : ")
Application_label.pack(pady=5)
Application_entry = tk.Entry(PMT, width=30)
Application_entry.pack()

Username_label = tk.Label(PMT, text="Username : ")
Username_label.pack(pady=5)
Username_entry = tk.Entry(PMT, width=30)
Username_entry.pack()

Password_label = tk.Label(PMT, text="Password : ")
Password_label.pack(pady=5)
Password_entry = tk.Entry(PMT, width=30, show="*")
Password_entry.pack()

GENERATE_PASSWORD_BUTTON = tk.Button(PMT, text="GENERATE PASSWORD", command=lambda: Password_entry.insert(tk.END, generating_a_random_password()))
GENERATE_PASSWORD_BUTTON.pack(pady=10)

ADD_CREDENTIAL_BUTTON = tk.Button(PMT, text="ADD CREDENTIAL", command=add_a_credential)
ADD_CREDENTIAL_BUTTON.pack(pady=10)

VIEW_CREDENTIAL_BUTTON = tk.Button(PMT, text="VIEW CREDENTIAL", command=view_all_the_credentials)
VIEW_CREDENTIAL_BUTTON.pack(pady=10)

SET_MASTER_KEY_BUTTON = tk.Button(PMT, text="SET MASTER KEY", command = setting_the_master_key)
SET_MASTER_KEY_BUTTON.pack(pady=10)

CHANGE_MASTER_KEY_BUTTON = tk.Button(PMT, text="CHANGE MASTER KEY", command=changing_the_master_key)
CHANGE_MASTER_KEY_BUTTON.pack(pady=10)

CLEAR_FIELDS_BUTTON = tk.Button(PMT, text="CLEAR FIELDS", command=clear_all_the_fields)
CLEAR_FIELDS_BUTTON.pack(pady=10)

# Check if master key is set and prompt to set it if not
if loading_the_hashed_master_key() is None:
    setting_the_master_key()

PMT.mainloop()
