import datetime
import hashlib
import os
import uuid
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.utils.crypto import get_random_string
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.sessions.models import Session
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login
import json
from django.contrib.auth import ( SESSION_KEY,) 
# import modals
from main.models import User, Review, GlobalIssues, RMS, RMSChat

from main.credentials import auth_user, auth_password



def send_otp(request):
    if request.method == "POST":
        email = request.POST.get("email")

        # Check if email is valid
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"status": "error", "message": "Invalid email format"})
        
        # email must ends with .lpu.in or .lpu.co.in
        if not email.endswith("@lpu.in") and not email.endswith("@lpu.co.in"):
            return JsonResponse({"status": "error", "message": "Only University email is allowed"})


        # Generate OTP
        otp = get_random_string(length=6, allowed_chars="0123456789")

        # Example: Send OTP via email
        try:
            send_mail(
                "Your OTP for UniTrack Registration",
                f"Your OTP is: {otp}",
                "support@enally.in",  # Replace with your sender email
                [email],
                fail_silently=False,
                auth_user= auth_user,
                auth_password= auth_password,
            )

            # Set OTP in session
            stored_otps = request.session.get("otps", {})
            stored_otps[email] = otp
            request.session["otps"] = stored_otps

            # Set OTP in a variable for verifying in the same request
            request.otp_for_verification = otp

            return JsonResponse({"status": "success"})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})
    else:
        return JsonResponse({"status": "error", "message": "Invalid request method"})

def verify_otp(request):
    if request.method == "POST":
        # Extract data from request body
        try:
            data = json.loads(request.body)
            email = data.get("email")
            otp = data.get("otp")
        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON data"})

        # Check if email is valid
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"status": "error", "message": "Invalid email format"})

        # Check if OTP is valid
        if len(otp) != 6 or not otp.isdigit():
            return JsonResponse({"status": "error", "message": "Invalid OTP format"})

        # Retrieve OTP from the session
        stored_otps = request.session.get("otps", {})
        stored_otp = stored_otps.get(email)

        # Retrieve OTP from the variable set in send_otp (for same request verification)
        otp_for_verification = getattr(request, "otp_for_verification", None)

        if otp_for_verification and otp_for_verification == otp:
            # Clear the OTP from the session after successful verification
            del stored_otps[email]
            request.session["otps"] = stored_otps
            return JsonResponse({"status": "success"})
        elif stored_otp and stored_otp == otp:
            # Clear the OTP from the session after successful verification
            del stored_otps[email]
            request.session["otps"] = stored_otps
            return JsonResponse({"status": "success"})
        else:
            return JsonResponse({"status": "error", "message": "Invalid OTP"})
    else:
        return JsonResponse({"status": "error", "message": "Invalid request method"})

def register(request):
    if request.method == "POST":
        # Extract data from request body
        try:
            data = json.loads(request.body)
            username = data.get("username")
            fullname = data.get("fullname")
            email = data.get("email")
            password = data.get("password")
        except json.JSONDecodeError:
            return JsonResponse({"status": "error", "message": "Invalid JSON data"})

        # Validate form data
        if not (username and fullname and email and password):
            return JsonResponse(
                {"status": "error", "message": "All fields are required"}
            )
        try:
            validate_email(email)
        except ValidationError:
            return JsonResponse({"status": "error", "message": "Invalid email format"})
        
        # email must ends with .lpu.in or .lpu.co.in
        if not email.endswith("@lpu.in") and not email.endswith("@lpu.co.in"):
            return JsonResponse({"status": "error", "message": "Only University email is allowed"})

        # username must be numeric and 5 or 8 length
        if not username.isdigit() or (len(username) != 5 and len(username) != 8):
            return JsonResponse({"status": "error", "message": "Invalid username format"})

        # Check if username and email are unique
        if User.objects(username=username).count() > 0:
            return JsonResponse(
                {"status": "error", "message": "Username already exists"}
            )
        if User.objects(email=email).count() > 0:
            return JsonResponse({"status": "error", "message": "Email already exists"})

        # Hash the password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        ## random uid using crypto
        uid = get_random_string(length=10, allowed_chars="0123456789") 

        # Create user
        user = User(
            username=username, full_name=fullname, email=email, password=hashed_password, uid=uid
        )
        user.save()

        return JsonResponse(
            {"status": "success", "message": "User registered successfully"}
        )

    else:
        # return register HTML
        return render(request, "register.html")

def login(request):
    if request.method == "POST":
        # Extract data from POST request
        email = request.POST.get("email")
        password = request.POST.get("password")
        
        # Validate form data
        if not (email and password):
            return JsonResponse({"status": "error", "message": "All fields are required"})

        # Authenticate user
        user = User.objects(email=email).first()
        if user:
            # Hash the password for comparison
            hashed_password = hashlib.sha256(password.encode()).hexdigest()
            if user.password == hashed_password:
                # Set session key to user's ID or UID
                session_key = user.uid if hasattr(user, 'uid') else str(user.id)
                # Add user's email and username to session data
                request.session['user_email'] = user.email
                request.session['user_username'] = user.username
                request.session[SESSION_KEY] = session_key
                
                return JsonResponse({"status": "success"})
        
        # If authentication fails or user doesn't exist
        return JsonResponse({"status": "error", "message": "Invalid credentials"})

    else:
        # Render login page for GET requests
        return render(request, "login.html")
    
def logout(request):
    # Clear session data
    request.session.flush()
    
    # Redirect to login page
    return render(request, "login.html")

def home(request):
    if request.method == "GET":
        print("Rendering home page")

        # fatch all data using session username and email and send it home as object
        user_data = User.objects(email=request.session.get("user_email")).first()
            
        if request.session.get("user_username"):
            return render(request, "index.html", {"username": request.session.get("user_username"), "user": user_data})
        else:
            ## redirect to login page
            return redirect('login')
        
def profile(request):
    if request.method == "GET":
        print("Rendering profile page")
        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        # count total review from collection Review where user name is session email 
        total_review = Review.objects(review_to=request.session.get("user_email")).count()
        allReview = Review.objects(review_to=request.session.get("user_email"))
        
        if user:
            return render(request, "profile.html", {"username": user.username, "user": user, "total_review": total_review, "allReview": allReview})
        else:
            return redirect('login')
    
    elif request.method == "POST":
        # Extract form data from POST request
        phone = request.POST.get("phone")
        address = request.POST.get("address")
        branch = request.POST.get("branch")
        semester = request.POST.get("semester")
        roll_no = request.POST.get("roll_no")
        is_admin = request.POST.get("is_admin")
        is_active = request.POST.get("is_active")
        is_staff = request.POST.get("is_staff")
        is_superuser = request.POST.get("is_superuser")
        is_blocked = request.POST.get("is_blocked")
        
        print(is_admin, is_active, is_staff, is_superuser, is_blocked)
    

        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            # Update user data
            user.phone = phone
            user.address = address
            user.branch = branch
            user.semester = semester
            user.roll_no = roll_no
            user.is_admin = True if is_admin == "1user." else False
            user.is_active = True if is_active == "1" else False
            user.is_staff = True if is_staff == "1" else False
            user.is_superuser = True if is_superuser == "1" else False
            user.is_blocked = True if is_blocked == "1" else False
            
            print(is_admin, is_active, is_staff, is_superuser, is_blocked)
            
            
            try:
                user.save()  # Save the updated user data
                return JsonResponse({"status": "success", "message": "Profile updated successfully"})
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)})
        else:
            return JsonResponse({"status": "error", "message": "Profile not found"})

def reset_password(request):
    # use session id and match old password and update new password
    if request.method == "POST":
        # Extract form data from POST request
        old_password = request.POST.get("old_password")
        new_password = request.POST.get("new_password")
        
        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            # Hash the old password for comparison
            hashed_old_password = hashlib.sha256(old_password.encode()).hexdigest()
            if user.password == hashed_old_password:
                # Hash the new password
                hashed_new_password = hashlib.sha256(new_password.encode()).hexdigest()
                # Update user data
                user.password = hashed_new_password
                try:
                    user.save()  # Save the updated user data
                    return JsonResponse({"status": "success", "message": "Password updated successfully"})
                except Exception as e:
                    return JsonResponse({"status": "error", "message": str(e)})
            else:
                return JsonResponse({"status": "error", "message": "Old password does not match"})
        else:
            return JsonResponse({"status": "error", "message": "User not found"})

def update_user_profile(request):
    if request.method == "POST":
        # Extract form data from POST request
        email = request.POST.get("email")
        is_admin = request.POST.get("is_admin")
        is_active = request.POST.get("is_active")
        is_staff = request.POST.get("is_staff")
        is_superuser = request.POST.get("is_superuser")
        is_blocked = request.POST.get("is_blocked")
        
        print(is_admin, is_active, is_staff, is_superuser, is_blocked)
    

        # Fetch user data using session email
        user = User.objects(email=email).first()
        if user:
            # Update user data
            user.is_admin = True if is_admin == "1user." else False
            user.is_active = True if is_active == "1" else False
            user.is_staff = True if is_staff == "1" else False
            user.is_superuser = True if is_superuser == "1" else False
            user.is_blocked = True if is_blocked == "1" else False
            
            print(is_admin, is_active, is_staff, is_superuser, is_blocked)
            
            
            try:
                user.save()  # Save the updated user data
                return JsonResponse({"status": "success", "message": "Profile updated successfully"})
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)})
        else:
            return JsonResponse({"status": "error", "message": "Profile not found"})
    
    elif request.method == "GET":
        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            return render(request, "Update_users.html", {"username": user.username, "user": user})
        else:
            return redirect('login')

def add_review(request):
    if request.method == "POST":
        # Extract form data from POST request
        review = request.POST.get("review")
        review_to = request.POST.get("review_to")
        description = request.POST.get("description")
        rating = request.POST.get("rating")
        created_at = str(datetime.datetime.now())
        
        # rating must be between 0 to 5
        if int(rating) < 0 or int(rating) > 5:
            return JsonResponse({"status": "error", "message": "Rating must be between 0 to 5"})
        
        
        # check if review_to is exisitng or not in User collection
        if not User.objects(email=review_to).first():
            return JsonResponse({"status": "error", "message": "Review to user not found"})
        
        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            # Save uploaded files
            files = request.FILES.getlist('document')
            save_directory = 'main/static/files'
            if not os.path.exists(save_directory):
                os.makedirs(save_directory)
            for file in files:
                with open(os.path.join(save_directory, file.name), 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
            
            # Create review
            review = Review(
                user=user.username,  
                review_to=review_to, 
                review_by=request.session.get("user_email"), 
                description=description, 
                document=file.name,  # Set document field here
                rating=rating, 
                created_at=created_at
            )
            
            try:
                review.save()  # Save the review
                return JsonResponse({"status": "success", "message": "Review added successfully"})
            except ValidationError as e:
                return JsonResponse({"status": "error", "message": str(e)})
        else:
            return JsonResponse({"status": "error", "message": "User not found"})
    
    elif request.method == "GET":
        # Fetch user data using session email
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            return render(request, "add_review.html", {"username": user.username, "user": user})
        else:
            return redirect('login')

def all_reviews(request):
    if request.method == "GET":
        print("Rendering all review page")
        # Fetch all reviews where review_to is session email
        allReview = Review.objects(review_to=request.session.get("user_email"))
        
        # Fetch reviews added by the current user
        added_by_you = Review.objects(review_by=request.session.get("user_email"))
        
        if allReview:
            return render(request, "all_reviews.html", {"allReview": allReview, 'addedby': added_by_you, "username": request.session.get("user_username")})
        else:
            return render(request, "all_reviews.html", {"allReview": [], "addedby": added_by_you, "username": request.session.get("user_username")})

def index(request):
    return render(request, "index.html")

def add_global_issues(request):
    if request.method == "POST":
        title = request.POST.get("title")
        description = request.POST.get("description")
        type = request.POST.get("type")
        created_at = str(datetime.datetime.now())
        
        # Add data to the GlobalIssues collection with title, description, created_at, status, and posted_by
        user = User.objects(email=request.session.get("user_email")).first()
        if user:
            global_issue = GlobalIssues(
                user=user.username,
                user_email=user.email,
                title=title, 
                description=description, 
                type=type,
                created_at=created_at, 
                status="Pending",
            )
            try:
                global_issue.save()  # Save the global issue
                return JsonResponse({"status": "success", "message": "Global issue added successfully"})
            except Exception as e:
                return JsonResponse({"status": "error", "message": str(e)})
    else:
        user = User.objects(email=request.session.get("user_email")).first()
        # fatch all the issues as object from collection "global_issues" type = "Public"
        issues = GlobalIssues.objects(type="public")
        
        return render(request, "create_issues.html", {"username": request.session.get("user_username"), "user": user, "issues": issues})


def rms(request):
    if request.method == "GET":
        user_email = request.session.get("user_email")
        all_rms = RMS.objects(user_email=user_email)
        return render(request, "rms.html", {"all_rms": all_rms})
    elif request.method == "POST":
        return render(request, "rms.html")
    else:
        return render(request, "rms.html")
    
    
from datetime import datetime, timedelta
def log_rms(request):
    if request.method == "GET":
        # Fetch all global issues
        return render(request, "log_rms.html")
    elif request.method == "POST":
        # Extract form data
        user = request.session.get("user_username")
        user_email = request.session.get("user_email")
        title = request.POST.get('title')
        description = request.POST.get('description')
        department = request.POST.get('department')
        status = "Pending"
        created_at = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        updated_at = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        assigned_to = "Unitrack Admin" 
        assigned_to_email = "support@enally.in" 
        
        send_mail(
                "RMS Logged by User",
                f"RMS has been logged by {user} with title {title}. Please check the RMS dashboard for more details.",
                "prashantmanwan@gmai.com",  # Replace with your sender email
                [assigned_to_email],
                fail_silently=False,
                auth_user= auth_user,
                auth_password= auth_password,
            )
        
        
        # Check if files are present in the request 
        if 'document' in request.FILES:
            files = request.FILES.getlist('document')
            save_directory = 'main/static/files'
            if not os.path.exists(save_directory):
                os.makedirs(save_directory)
            for file in files:
                # Generate random filename
                random_filename = str(uuid.uuid4())
                # Get file extension
                file_extension = os.path.splitext(file.name)[1]
                # Construct new file path
                file_path = os.path.join(save_directory, random_filename + file_extension)
                # Write file to disk
                with open(file_path, 'wb+') as destination:
                    for chunk in file.chunks():
                        destination.write(chunk)
                # Save file name to database
                RMS.objects.create(
                    user=user,
                    user_email=user_email,
                    title=title,
                    description=description,
                    department=department,
                    supporting_document=random_filename + file_extension,
                    status=status,
                    created_at=created_at,
                    updated_at=updated_at,
                    assigned_to=assigned_to,
                    assigned_to_email=assigned_to_email
                )
        else:
            RMS.objects.create(
                user=user,
                user_email=user_email,
                title=title,
                description=description,
                department=department,
                status=status,
                created_at=created_at,
                updated_at=updated_at,
                assigned_to=assigned_to,
                assigned_to_email=assigned_to_email
            )

        # Return success response
        return JsonResponse({'message': 'RMS logged successfully'}, status=200)
    else:
        return render(request, "log_rms.html")


def rms_status(request):
    if request.method == "GET":
        # Fetch all RMS forms associated with the user's email
        user_email = request.session.get("user_email")
        all_rms = RMS.objects(user_email=user_email)
        
        def formatDate(date):
            # Format as 20 July 20 
            return datetime.now().strftime("%d %B %y")
        
        all_rms_formatted = [
            {
                "id": rms.id,
                "title": rms.title,
                "status": rms.status,
                "description": rms.description,
                "supporting_document" : rms.supporting_document,
                "created_at": formatDate(rms.created_at),
                "updated_at": formatDate(rms.updated_at),
                "assigned_to": rms.assigned_to,
            }
            for rms in all_rms
        ]
        
        return render(request, "rms_status.html", {"all_rms": all_rms_formatted})

def format_timedelta(td):
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    parts = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    if minutes > 0:
        parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

    return ' '.join(parts)

def rms_details(request, rms_id):
    # Fetch details of the specific RMS using the provided ID
    rms = RMS.objects.get(id=rms_id)
    
    # Check if the RMS is pending for 48 hours
    is_pending_for_48_hours = False
    created_at = datetime.strptime(rms.created_at, "%Y-%m-%d %H:%M:%S")
    if rms.status == 'Pending':
        current_datetime = datetime.now()
        time_difference = current_datetime - created_at
        if time_difference >= timedelta(hours=48):
            is_pending_for_48_hours = True

    # Calculate time remaining for pending RMS
    time_remaining = None
    if is_pending_for_48_hours:
        time_remaining = "Expired"
    else:
        time_remaining = format_timedelta(timedelta(hours=48) - time_difference)

    return render(request, "rms_details.html", {"rms": rms, "is_pending_for_48_hours": is_pending_for_48_hours, "time_remaining": time_remaining})

def rms_chat(request, rms_id):
    if request.method == "GET":
        # Fetch all chat messages for the specific RMS
        rms_chat = RMSChat.objects.filter(rms_id=rms_id).first()
        
        # fatch rms details from RMS collection
        rms = RMS.objects.get(id=rms_id)
       
        
        # Mark all messages as read
        if rms_chat:
            rms_chat.is_read = True
            rms_chat.save()
            return render(request, "rms_chat.html", {"rms_chat": rms_chat, "rms": rms})
        else:
            return render(request, "rms_chat.html", {"rms_chat": None, "rms": rms})

    elif request.method == "POST":
        # Extract form data
        message = request.POST.get("message")
        user_id = request.session.get("user_id")
        user_email = request.session.get("user_email")
        faculty_id = request.POST.get("faculty_id")
        faculty_email = request.POST.get("faculty_email")
        chat_title = request.POST.get("chat_title")
        created_at = datetime.now()
        
        # Retrieve existing chat or create new if not exists
        rms_chat = RMSChat.objects.filter(rms_id=rms_id).first()
        if not rms_chat:
            rms_chat = RMSChat.objects.create(
                rms_id=rms_id,
                user_email=user_email,
                faculty_id=faculty_id,
                faculty_email=faculty_email,
                chats=[],
                date_created=created_at,
                date_updated=created_at,
                closed_chat_by_user=False,
                closed_chat_by_faculty=False
            )
        
        # Append new message to the chats array
        rms_chat.chats.append({
            "user_id": user_id,
            "user_email": user_email,
            "message": message,
            "timestamp": created_at
        })
        rms_chat.date_updated = created_at
        rms_chat.save()
        
        # Return success response
        return JsonResponse({"success": True, "message": "Message sent successfully"}, status=200)
    else:
        return render(request, "rms_chat.html")
    

def rms_chats(request, rms_id):
    if request.method == "GET":
        # Fetch all chat messages for the specific RMS
        rms_chat = RMSChat.objects.filter(rms_id=rms_id).first()
        
        # fatch rms details from RMS collection
        rms = RMS.objects.get(id=rms_id)
        print(rms_chat.chats)
        
        return JsonResponse({"status": "success", "data": rms_chat.chats})