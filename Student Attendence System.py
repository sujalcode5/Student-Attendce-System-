import tkinter as tk
from tkinter import ttk, messagebox
import csv
import os
from datetime import datetime
from PIL import Image, ImageTk

# File paths for CSV storage
FILES = {
    "students": "students.csv",
    "attendance": "attendance.csv",
    "users": "users.csv",
    "subjects": "subjects.csv",
}

# Initialize CSV files with headers if they don't exist
for file, headers in [
    (FILES["students"], ["Roll Number", "Name"]),
    (FILES["attendance"], ["Date", "Roll Number", "Name", "Status", "Subject"]),
    (FILES["users"], ["Username", "Password", "Role"]),
    (FILES["subjects"], ["Subject"]),
]:
    if not os.path.exists(file):
        with open(file, "w", newline="") as f:
            csv.writer(f).writerow(headers)

# Helper functions for CSV operations
def load_csv(file):
    with open(file, newline="") as f:
        return list(csv.reader(f))[1:]

def append_csv(file, row):
    with open(file, "a", newline="") as f:
        csv.writer(f).writerow(row)

def overwrite_csv(file, rows, header):
    with open(file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)

class AttendanceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Student Attendance System")
        self.root.geometry("1200x800")
        self.root.config(bg="#e0f7fa")  # Light cyan background
        self.current_user = None
        self.current_role = None
        self.icons = {}
        self.load_icons()
        self.login_window()

    def load_icons(self):
        icon_files = {
            "mark_attendance": "mark_attendance.png",
            "view_attendance": "view_attendance.png",
            "view_students": "view_students.png",
            "add_student": "add_student.png",
            "remove_student": "remove_student.png",
            "add_subject": "add_subject.png",
            "remove_subject": "remove_subject.png",
            "manage_users": "manage_users.png",
            "generate_report": "generate_report.png",
            "logout": "logout.png"
        }
        for key, file in icon_files.items():
            try:
                img = Image.open(file).resize((32, 32))
                self.icons[key] = ImageTk.PhotoImage(img)
            except FileNotFoundError:
                self.icons[key] = None  # Fallback to no icon if file is missing

    def login_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Login", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Username", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.username = tk.Entry(main_frame, font=("Arial", 14))
        self.username.pack(pady=5)
        tk.Label(main_frame, text="Password", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.password = tk.Entry(main_frame, show="*", font=("Arial", 14))
        self.password.pack(pady=5)
        tk.Label(main_frame, text="Role", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.role = ttk.Combobox(main_frame, values=["admin", "teacher"], state="readonly", font=("Arial", 14))
        self.role.pack(pady=5)
        tk.Button(main_frame, text="Login", command=self.login, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Register", command=self.register_window, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def register_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Register", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="New Username", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.new_user = tk.Entry(main_frame, font=("Arial", 14))
        self.new_user.pack(pady=5)
        tk.Label(main_frame, text="New Password", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.new_pass = tk.Entry(main_frame, show="*", font=("Arial", 14))
        self.new_pass.pack(pady=5)
        tk.Label(main_frame, text="Role", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        self.new_role = ttk.Combobox(main_frame, values=["admin", "teacher"], state="readonly", font=("Arial", 14))
        self.new_role.pack(pady=5)
        tk.Button(main_frame, text="Register", command=self.register, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.login_window, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def register(self):
        user, pwd, role = self.new_user.get().strip(), self.new_pass.get().strip(), self.new_role.get()
        if not user or not pwd or not role:
            messagebox.showerror("Error", "All fields are required")
            return
        users = load_csv(FILES["users"])
        if any(u[0] == user for u in users):
            messagebox.showerror("Error", "User already exists")
            return
        append_csv(FILES["users"], [user, pwd, role])
        messagebox.showinfo("Success", "User registered")
        self.login_window()

    def login(self):
        user, pwd, role = self.username.get().strip(), self.password.get().strip(), self.role.get()
        users = load_csv(FILES["users"])
        for u in users:
            if u[0] == user and u[1] == pwd and u[2] == role:
                self.current_user = user
                self.current_role = role
                self.dashboard()
                return
        messagebox.showerror("Login Failed", "Invalid credentials")

    def dashboard(self):
        self.clear()
        # Use a main frame to center everything
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        # Welcome message at the top
        tk.Label(main_frame, text=f"Welcome {self.current_role.title()} ({self.current_user})",
                 font=("Arial", 18), bg="#e0f7fa").pack(pady=20)

        # Create a frame for the centered layout
        content_frame = tk.Frame(main_frame, bg="#e0f7fa")
        content_frame.pack(expand=True)

        # Left frame for Student Tasks
        left_frame = tk.Frame(content_frame, bg="#e0f7fa", width=300)
        left_frame.pack(side=tk.LEFT, padx=20, pady=20)

        # Right frame for Admin Management
        right_frame = tk.Frame(content_frame, bg="#e0f7fa", width=300)
        right_frame.pack(side=tk.RIGHT, padx=20, pady=20)

        # Center decorative panel to fill the space
        center_frame = tk.Frame(content_frame, bg="#ffffff", width=400, height=300, bd=2, relief=tk.RAISED)
        center_frame.pack(pady=20)
        tk.Label(center_frame, text="Attendance Dashboard Overview", font=("Arial", 14, "bold"),
                 bg="#ffffff", fg="#2196F3").pack(pady=10)
        tk.Label(center_frame, text="Monitor and manage student attendance efficiently.\n"
                                    "Use the side panels to perform tasks and generate reports.",
                 font=("Arial", 12), bg="#ffffff", wraplength=350).pack(pady=10)

        # Student Tasks (Left Side)
        tk.Label(left_frame, text="Student Tasks", font=("Arial", 16, "bold"), bg="#e0f7fa").pack(pady=10)
        student_tasks = [
            ("Mark Attendance", self.mark_attendance_window, "mark_attendance"),
            ("View Attendance", self.view_filtered_attendance, "view_attendance"),
            ("View Students", self.view_students_window, "view_students"),
        ]
        for text, cmd, icon_key in student_tasks:
            btn_frame = tk.Frame(left_frame, bg="#e0f7fa")
            btn_frame.pack(pady=5, fill=tk.X)
            if self.icons[icon_key]:
                tk.Label(btn_frame, image=self.icons[icon_key], bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
            tk.Button(btn_frame, text=text, command=cmd, bg="#2196F3", fg="white", font=("Arial", 12),
                      width=20, height=1, relief=tk.RAISED, pady=2).pack(side=tk.LEFT)

        # Admin Tasks (Right Side)
        if self.current_role == "admin":
            tk.Label(right_frame, text="Admin Management", font=("Arial", 16, "bold"), bg="#e0f7fa").pack(pady=10)
            admin_tasks = [
                ("Add Student", self.add_student_window, "add_student"),
                ("Remove Student", self.remove_student_window, "remove_student"),
                ("Add Subject", self.add_subject_window, "add_subject"),
                ("Remove Subject", self.remove_subject_window, "remove_subject"),
                ("Manage Users", self.manage_users_window, "manage_users"),
                ("Generate Report", self.generate_report_window, "generate_report"),
            ]
            for text, cmd, icon_key in admin_tasks:
                btn_frame = tk.Frame(right_frame, bg="#e0f7fa")
                btn_frame.pack(pady=5, fill=tk.X)
                if self.icons[icon_key]:
                    tk.Label(btn_frame, image=self.icons[icon_key], bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
                tk.Button(btn_frame, text=text, command=cmd, bg="#2196F3", fg="white", font=("Arial", 12),
                          width=20, height=1, relief=tk.RAISED, pady=2).pack(side=tk.LEFT)

        # Logout button at the bottom
        logout_frame = tk.Frame(main_frame, bg="#e0f7fa")
        logout_frame.pack(pady=20)
        if self.icons["logout"]:
            tk.Label(logout_frame, image=self.icons["logout"], bg="#e0f7fa").pack(side=tk.LEFT, padx=5)
        tk.Button(logout_frame, text="Logout", command=self.login_window, bg="#f44336", fg="white", font=("Arial", 12),
                  width=20, height=1, relief=tk.RAISED).pack(side=tk.LEFT)

    def add_student_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Add Student", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Roll Number", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        roll = tk.Entry(main_frame, font=("Arial", 14))
        roll.pack(pady=5)
        tk.Label(main_frame, text="Name", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        name = tk.Entry(main_frame, font=("Arial", 14))
        name.pack(pady=5)

        def save():
            roll_num, student_name = roll.get().strip(), name.get().strip()
            if not roll_num or not student_name:
                messagebox.showerror("Error", "Both fields required")
                return
            students = load_csv(FILES["students"])
            if any(s[0] == roll_num for s in students):
                messagebox.showerror("Error", "Roll number already exists")
                return
            append_csv(FILES["students"], [roll_num, student_name])
            messagebox.showinfo("Saved", "Student added")
            self.dashboard()

        tk.Button(main_frame, text="Add", command=save, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def remove_student_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Remove Student", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Roll Number", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        roll = tk.Entry(main_frame, font=("Arial", 14))
        roll.pack(pady=5)

        def remove():
            roll_num = roll.get().strip()
            if not roll_num:
                messagebox.showerror("Error", "Roll number required")
                return
            students = load_csv(FILES["students"])
            if not any(s[0] == roll_num for s in students):
                messagebox.showerror("Error", "Roll number not found")
                return
            updated = [s for s in students if s[0] != roll_num]
            overwrite_csv(FILES["students"], updated, ["Roll Number", "Name"])
            messagebox.showinfo("Removed", "Student removed")
            self.dashboard()

        tk.Button(main_frame, text="Remove", command=remove, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def view_students_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Students", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tree = ttk.Treeview(main_frame, columns=("Roll", "Name"), show="headings")
        tree.heading("Roll", text="Roll Number")
        tree.heading("Name", text="Name")
        for row in load_csv(FILES["students"]):
            tree.insert("", "end", values=row)
        tree.pack(pady=20)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def add_subject_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Add Subject", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Subject Name", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        subject_name = tk.Entry(main_frame, font=("Arial", 14))
        subject_name.pack(pady=5)

        def save_subject():
            subject = subject_name.get().strip()
            if not subject:
                messagebox.showerror("Error", "Subject name cannot be empty")
                return
            subjects = load_csv(FILES["subjects"])
            if any(s[0].lower() == subject.lower() for s in subjects):
                messagebox.showerror("Error", "Subject already exists")
                return
            append_csv(FILES["subjects"], [subject])
            messagebox.showinfo("Success", "Subject added")
            self.dashboard()

        tk.Button(main_frame, text="Add Subject", command=save_subject, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def remove_subject_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Remove Subject", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Subject", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        subject = ttk.Combobox(main_frame, values=[s[0] for s in load_csv(FILES["subjects"])], state="readonly", font=("Arial", 14))
        subject.pack(pady=5)

        def remove():
            sub = subject.get()
            if not sub:
                messagebox.showerror("Error", "Please select a subject")
                return
            subjects = load_csv(FILES["subjects"])
            updated = [s for s in subjects if s[0] != sub]
            overwrite_csv(FILES["subjects"], updated, ["Subject"])
            attendance = load_csv(FILES["attendance"])
            updated_attendance = [a for a in attendance if a[4] != sub]
            overwrite_csv(FILES["attendance"], updated_attendance, ["Date", "Roll Number", "Name", "Status", "Subject"])
            messagebox.showinfo("Success", "Subject and related data removed")
            self.dashboard()

        tk.Button(main_frame, text="Remove Subject", command=remove, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def mark_attendance_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Mark Attendance", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Subject", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        subject = tk.StringVar()
        subject_entry = ttk.Combobox(main_frame, textvariable=subject, values=[s[0] for s in load_csv(FILES["subjects"])],
                                     font=("Arial", 14), state="readonly")
        subject_entry.pack(pady=5)

        students = load_csv(FILES["students"])
        entries = {}
        for s in students:
            tk.Label(main_frame, text=f"{s[1]} (Roll {s[0]})", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
            var = tk.StringVar(value="Present")
            entries[s[0]] = var
            ttk.Combobox(main_frame, textvariable=var, values=["Present", "Absent"], state="readonly",
                         font=("Arial", 14)).pack(pady=5)

        def submit():
            sub = subject.get()
            if not sub:
                messagebox.showerror("Missing", "Subject required")
                return
            date = datetime.now().strftime("%Y-%m-%d")
            for s in students:
                append_csv(FILES["attendance"], [date, s[0], s[1], entries[s[0]].get(), sub])
            messagebox.showinfo("Saved", "Attendance marked")
            self.dashboard()

        tk.Button(main_frame, text="Submit", command=submit, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def view_filtered_attendance(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="View Attendance", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Date (YYYY-MM-DD)", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        date_entry = tk.Entry(main_frame, font=("Arial", 14))
        date_entry.pack(pady=5)
        tk.Label(main_frame, text="Subject", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        subject = ttk.Combobox(main_frame, values=["All"] + [s[0] for s in load_csv(FILES["subjects"])], state="readonly", font=("Arial", 14))
        subject.pack(pady=5)

        def show():
            selected_date = date_entry.get().strip()
            selected_subject = subject.get()
            if selected_date:
                try:
                    datetime.strptime(selected_date, "%Y-%m-%d")
                except ValueError:
                    messagebox.showerror("Error", "Invalid date format (use YYYY-MM-DD)")
                    return
            self.clear()
            view_frame = tk.Frame(self.root, bg="#e0f7fa")
            view_frame.pack(expand=True)
            tk.Label(view_frame, text="Attendance", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
            tree = ttk.Treeview(view_frame, columns=("Date", "Roll", "Name", "Status", "Subject"), show="headings")
            for col in ("Date", "Roll", "Name", "Status", "Subject"):
                tree.heading(col, text=col)
            for row in load_csv(FILES["attendance"]):
                if (not selected_date or row[0] == selected_date) and \
                   (selected_subject == "All" or row[4] == selected_subject):
                    tree.insert("", "end", values=row)
            tree.pack(pady=20)
            tk.Button(view_frame, text="Back", command=self.view_filtered_attendance, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

        tk.Button(main_frame, text="Show Attendance", command=show, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def manage_users_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Manage Users", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tree = ttk.Treeview(main_frame, columns=("Username", "Role"), show="headings")
        tree.heading("Username", text="Username")
        tree.heading("Role", text="Role")
        for row in load_csv(FILES["users"]):
            tree.insert("", "end", values=row[:2])
        tree.pack(pady=20)

        tk.Label(main_frame, text="Username to Edit/Delete", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        username = tk.Entry(main_frame, font=("Arial", 14))
        username.pack(pady=5)
        tk.Label(main_frame, text="New Password (leave blank to keep)", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        new_pass = tk.Entry(main_frame, show="*", font=("Arial", 14))
        new_pass.pack(pady=5)
        tk.Label(main_frame, text="New Role", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        new_role = ttk.Combobox(main_frame, values=["admin", "teacher"], state="readonly", font=("Arial", 14))
        new_role.pack(pady=5)

        def edit():
            u, p, r = username.get().strip(), new_pass.get().strip(), new_role.get()
            if not u:
                messagebox.showerror("Error", "Username required")
                return
            users = load_csv(FILES["users"])
            for i, user in enumerate(users):
                if user[0] == u:
                    users[i] = [u, p if p else user[1], r if r else user[2]]
                    overwrite_csv(FILES["users"], users, ["Username", "Password", "Role"])
                    messagebox.showinfo("Success", "User updated")
                    self.manage_users_window()
                    return
            messagebox.showerror("Error", "User not found")

        def delete():
            u = username.get().strip()
            if not u:
                messagebox.showerror("Error", "Username required")
                return
            if u == self.current_user:
                messagebox.showerror("Error", "Cannot delete current user")
                return
            users = load_csv(FILES["users"])
            updated = [user for user in users if user[0] != u]
            if len(users) == len(updated):
                messagebox.showerror("Error", "User not found")
                return
            overwrite_csv(FILES["users"], updated, ["Username", "Password", "Role"])
            messagebox.showinfo("Success", "User deleted")
            self.manage_users_window()

        tk.Button(main_frame, text="Edit User", command=edit, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Delete User", command=delete, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def generate_report_window(self):
        self.clear()
        main_frame = tk.Frame(self.root, bg="#e0f7fa")
        main_frame.pack(expand=True)

        tk.Label(main_frame, text="Generate Attendance Report", font=("Arial", 18), bg="#e0f7fa").pack(pady=20)
        tk.Label(main_frame, text="Date (YYYY-MM-DD)", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        date_entry = tk.Entry(main_frame, font=("Arial", 14))
        date_entry.pack(pady=5)
        tk.Label(main_frame, text="Subject", font=("Arial", 14), bg="#e0f7fa").pack(pady=5)
        subject = ttk.Combobox(main_frame, values=["All"] + [s[0] for s in load_csv(FILES["subjects"])], state="readonly", font=("Arial", 14))
        subject.pack(pady=5)

        def generate():
            selected_date = date_entry.get().strip()
            selected_subject = subject.get()
            if selected_date:
                try:
                    datetime.strptime(selected_date, "%Y-%m-%d")
                except ValueError:
                    messagebox.showerror("Error", "Invalid date format (use YYYY-MM-DD)")
                    return
            attendance = load_csv(FILES["attendance"])
            filtered = [row for row in attendance if (not selected_date or row[0] == selected_date) and
                       (selected_subject == "All" or row[4] == selected_subject)]
            if not filtered:
                messagebox.showinfo("Info", "No data available for the selected criteria")
                return
            with open("attendance_report.txt", "w") as f:
                f.write(f"Attendance Report - Date: {selected_date or 'All'}\n")
                f.write(f"Subject: {selected_subject or 'All'}\n\n")
                f.write("Roll Number, Name, Status\n")
                for row in filtered:
                    f.write(f"{row[1]}, {row[2]}, {row[3]}\n")
            messagebox.showinfo("Success", "Report generated as 'attendance_report.txt'")
            self.dashboard()

        tk.Button(main_frame, text="Generate Report", command=generate, bg="#4CAF50", fg="white", width=20, height=2).pack(pady=5)
        tk.Button(main_frame, text="Back", command=self.dashboard, bg="#f44336", fg="white", width=20, height=2).pack(pady=5)

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = AttendanceApp(root)
    root.mainloop()
    
