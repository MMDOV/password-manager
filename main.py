from ttkbootstrap import *
from tkinter import messagebox
from random import choice, randint, shuffle
import pyperclip
import json


# ---------------------------- PASSWORD GENERATOR ------------------------------- #
def generate_password():
    password_entry.delete(0, END)
    letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
               'v',
               'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q',
               'R',
               'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
    symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']

    password_letters = [choice(letters) for _ in range(randint(8, 10))]
    password_symbols = [choice(symbols) for _ in range(randint(2, 4))]
    password_numbers = [choice(numbers) for _ in range(randint(2, 4))]

    password_list = password_numbers + password_symbols + password_letters
    shuffle(password_list)

    password = "".join(password_list)
    password_entry.insert(0, password)
    pyperclip.copy(password)


# ---------------------------- SAVE PASSWORD ------------------------------- #


def save():
    website = website_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    new_data = {
        website: {
            "email": email,
            "password": password,
        }
    }

    if len(website) == 0 or len(password) == 0 or len(email) == 0:
        messagebox.showerror(title="Oops!", message="Please don't leave any fields empty!")
    else:
        try:
            data_file = open("data.json", "r")
            data = json.load(data_file)
        except FileNotFoundError:
            data_file = open("data.json", "w")
            json.dump(new_data, data_file, indent=4)
        else:
            data.update(new_data)
            data_file.close()
            data_file = open("data.json", "w")
            json.dump(data, data_file, indent=4)
            data_file.close()
        finally:
            website_entry.delete(0, END)
            password_entry.delete(0, END)

# --------------------------------FIND PASSWORD--------------------------------- #


def find_password():
    search_input = website_entry.get()
    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
    except FileNotFoundError:
        messagebox.showerror(title="Error", message="No Data File Found")
    else:
        if search_input in data:
            messagebox.showinfo(title=search_input, message=f"Email: {data[search_input]['email']} \n"
                                                            f"Password: {data[search_input]['password']}")
        else:
            messagebox.showerror(title=search_input, message="No details for the website exists")


# ---------------------------- UI SETUP ------------------------------- #
window = Window()
window.title("Password Manager")
window.config(padx=50, pady=50)

canvas = Canvas(width=200, height=200, highlightthickness=0)
logo_img = PhotoImage(file="logo.png")
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1)

website_label = Label(text="Website:")
website_label.grid(row=1, column=0)

website_entry = Entry(width=30)
website_entry.grid(row=1, column=1)
website_entry.focus()

search_button = Button(text="Search", command=find_password, width=10, bootstyle="dark")
search_button.grid(row=1, column=2)

email_label = Label(text="Email/Username:")
email_label.grid(row=2, column=0)

email_entry = Entry(width=44)
email_entry.grid(row=2, column=1, columnspan=2)
email_entry.insert(0, "mohammadvgamer@gmail.com")

password_label = Label(text="Password:")
password_label.grid(row=3, column=0)

password_entry = Entry(width=30)
password_entry.grid(row=3, column=1)

password_button = Button(text="Make Pass", command=generate_password, width=10, bootstyle="dark")
password_button.grid(row=3, column=2)

add_button = Button(text="Add", width=43, command=save)
add_button.grid(row=4, column=1, columnspan=2)

window.mainloop()
