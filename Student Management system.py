import sqlite3
import streamlit as st
import hashlib  # For password hashing

# Create roles and permissions (in-memory for simplicity)
ROLES_PERMISSIONS = {
    'admin': ['add', 'update', 'delete', 'view'],
    'viewer': ['view']
}

# Mock user roles (in-memory for simplicity)
USER_ROLES = {
    'admin': 'admin',
    'viewer': 'viewer'
}

# In-memory storage for admin credentials (username, password hash, and roll number)
ADMIN_CREDENTIALS = {
    'admin': {
        'password_hash': hashlib.sha256('1234'.encode()).hexdigest(),  # Replace '1234' with your desired admin password
        'roll_no': 'admin123'  # Replace with your desired admin roll number
    }
}

def verify_credentials(username, password):
    if username in ADMIN_CREDENTIALS:
        user_info = ADMIN_CREDENTIALS[username]
        if user_info['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            return 'admin'
    
    return None

def get_user_role(username):
    return USER_ROLES.get(username, 'viewer')

def check_permission(username, permission):
    role = get_user_role(username)
    return permission in ROLES_PERMISSIONS.get(role, [])

def create_table():
    conn = sqlite3.connect('students.db')
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        roll_no TEXT NOT NULL,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        age INTEGER NOT NULL,
        gender TEXT NOT NULL
    )
    ''')
    conn.commit()
    conn.close()

def insert_student(roll_no, name, email, age, gender):
    conn = sqlite3.connect('students.db')
    cur = conn.cursor()
    cur.execute('''
    INSERT INTO students (roll_no, name, email, age, gender) VALUES (?, ?, ?, ?, ?)
    ''', (roll_no, name, email, age, gender))
    conn.commit()
    conn.close()

def get_students():
    conn = sqlite3.connect('students.db')
    cur = conn.cursor()
    cur.execute('SELECT * FROM students')
    rows = cur.fetchall()
    conn.close()
    return rows

def update_student(roll_no, name, email, age, gender):
    conn = sqlite3.connect('students.db')
    cur = conn.cursor()
    cur.execute('''
    UPDATE students SET name = ?, email = ?, age = ?, gender = ? WHERE roll_no = ?
    ''', (name, email, age, gender, roll_no))
    conn.commit()
    conn.close()

def delete_student(roll_no):
    conn = sqlite3.connect('students.db')
    cur = conn.cursor()
    cur.execute('''
    DELETE FROM students WHERE roll_no = ?
    ''', (roll_no,))
    conn.commit()
    conn.close()

def validate_input(name, email, age, gender, roll_no=None):
    if not name:
        st.error('Name cannot be empty')
        return False
    if not email or '@' not in email:
        st.error('Invalid email')
        return False
    if not age.isdigit():
        st.error('Age must be an integer')
        return False
    if gender not in ['Male', 'Female', 'Other']:
        st.error('Gender must be Male, Female, or Other')
        return False
    if roll_no and not (roll_no.startswith("22CSR") and len(roll_no) == 8 and roll_no[5:].isdigit()):
        st.error('Roll No must be in the format 22CSRxxx')
        return False
    return True

def main():
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #F0F8FF;
        }
        </style>
        """,
        unsafe_allow_html=True
    )
    st.title('Student Management System')

    username = st.text_input('Username')
    
    if username:
        if username == 'admin':
            password = st.text_input('Password', type='password')
            if not password:
                st.warning('Please enter password')
                return
            
            user_role = verify_credentials(username, password)
            if user_role == 'admin':
                st.write(f'Logged in as: {username} (admin)')
                
                create_table()

                menu = ['Add Student', 'Update Student', 'Delete Student', 'View Students']
                choice = st.selectbox('Select Operation', menu)

                if choice == 'Add Student' and check_permission(username, 'add'):
                    st.subheader('Add Student')
                    with st.expander("Add New Student"):
                        roll_no = st.text_input('Roll No')
                        name = st.text_input('Name')
                        email = st.text_input('Email')
                        age = st.text_input('Age')
                        gender = st.selectbox('Gender', ['Male', 'Female', 'Other'])
                        submit_button = st.button('Add Student')
                    
                    if submit_button and validate_input(name, email, age, gender, roll_no):
                        try:
                            conn = sqlite3.connect('students.db')
                            cur = conn.cursor()
                            cur.execute('BEGIN')
                            insert_student(roll_no, name, email, int(age), gender)
                            conn.commit()
                            st.success(f'Student {name} added successfully with Roll No {roll_no}')
                        except Exception as e:
                            conn.rollback()
                            st.error(f'Error: {e}')
                        finally:
                            conn.close()

                elif choice == 'Update Student' and check_permission(username, 'update'):
                    st.subheader('Update Student')
                    with st.expander("Update Existing Student"):
                        roll_no = st.text_input('Roll No')
                        name = st.text_input('Name')
                        email = st.text_input('Email')
                        age = st.text_input('Age')
                        gender = st.selectbox('Gender', ['Male', 'Female', 'Other'])
                        submit_button = st.button('Update Student')
                    
                    if submit_button and validate_input(name, email, age, gender, roll_no):
                        try:
                            conn = sqlite3.connect('students.db')
                            cur = conn.cursor()
                            cur.execute('BEGIN')
                            update_student(roll_no, name, email, int(age), gender)
                            conn.commit()
                            st.success(f'Student with Roll No {roll_no} updated successfully')
                        except Exception as e:
                            conn.rollback()
                            st.error(f'Error: {e}')
                        finally:
                            conn.close()

                elif choice == 'Delete Student' and check_permission(username, 'delete'):
                    st.subheader('Delete Student')
                    with st.expander("Delete Existing Student"):
                        roll_no = st.text_input('Roll No')
                        submit_button = st.button('Delete Student')
                    
                    if submit_button and roll_no:
                        try:
                            conn = sqlite3.connect('students.db')
                            cur = conn.cursor()
                            cur.execute('BEGIN')
                            delete_student(roll_no)
                            conn.commit()
                            st.success(f'Student with Roll No {roll_no} deleted successfully')
                        except Exception as e:
                            conn.rollback()
                            st.error(f'Error: {e}')
                        finally:
                            conn.close()

                elif choice == 'View Students' and check_permission(username, 'view'):
                    st.subheader('View Students')
                    with st.expander("View Students by Criteria"):
                        view_choice = st.selectbox('View by', ['All', 'Gender', 'Age'])
                        if view_choice == 'Gender':
                            gender = st.selectbox('Gender', ['Male', 'Female', 'Other'])
                            students = [s for s in get_students() if s[5] == gender]
                        elif view_choice == 'Age':
                            age = st.text_input('Age')
                            if age.isdigit():
                                students = [s for s in get_students() if s[4] == int(age)]
                            else:
                                students = []
                                st.warning('Age must be a number')
                        else:
                            students = get_students()
                    st.table(students)
                else:
                    st.error('You do not have permission to perform this operation')
            else:
                st.error('Access denied. Invalid username or password')
        else:
            st.write(f'Logged in as: {username} (viewer)')
            
            # Display content for viewer role here
            st.subheader('Viewer Content')
            st.write("You can view student details here.")
            st.table(get_students())  # Example content, modify as per your application
    else:
        st.warning('Please enter username')

if __name__ == '__main__':
    main()
