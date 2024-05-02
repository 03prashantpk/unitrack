from mongoengine import Document, StringField,ListField, EmailField,DictField, IntField, BooleanField, connect, DateTimeField

from main.credentials import db_name, host

# Connect to MongoDB
connect(db_name, host=host, port=27017)

class User(Document):
    username = StringField(required=True, unique=True)
    full_name = StringField(required=True)
    email = EmailField(required=True, unique=True)
    password = StringField(required=True)
    uid = IntField(required=True, unique=True)
    phone = StringField()
    address = StringField()
    branch = StringField()
    semester = StringField()
    roll_no = StringField()
    is_admin = BooleanField(default=False)
    is_active = BooleanField(default=False)
    is_staff = BooleanField(default=False)
    is_superuser = BooleanField(default=False)
    is_blocked = BooleanField(default=False)

class Review(Document):
    user = StringField(required=True)
    review_to = StringField(required=True)
    review_by = StringField(required=True)
    description = StringField(required=True)
    document = StringField(required=True)
    rating = IntField(required=True)
    created_at = StringField(required=True)
    status = StringField(required=True, default="Pending")


class GlobalIssues(Document):
    user = StringField(required=True)
    user_email = StringField(required=True)
    title = StringField(required=True)
    description = StringField(required=True)
    type = StringField(required=True)
    created_at = StringField(required=True)
    status = StringField(required=True, default="Pending")
    
class RMS(Document):
    user = StringField(required=True)
    user_email = StringField(required=True)
    title = StringField(required=True)
    description = StringField(required=True)
    department = StringField(required=True)
    supporting_document = StringField(required=True)
    status = StringField(required=True, default="Pending")
    reply = StringField(default="")
    created_at = StringField(required=True)
    updated_at = StringField(required=True)
    assigned_to = StringField(required=True)
    assigned_to_email = StringField(required=True)
    
    
class RMSChat(Document):
    rms_id = StringField(required=True)
    user_email = StringField(required=True)
    faculty_id = StringField()
    faculty_email = StringField()
    # Define chats field as a ListField of DictField
    chats = ListField(DictField(), default=[])
    date_created = DateTimeField(required=True)
    date_updated = DateTimeField(required=True)
    closed_chat_by_user = BooleanField(default=False)
    closed_chat_by_faculty = BooleanField(default=False)
