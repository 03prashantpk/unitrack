# UniTrack

<img scr="https://raw.githubusercontent.com/03prashantpk/unitrack/main/static/files/unitrack.png" width="100%" />

UniTrack is a pioneering web-based platform designed to revolutionize performance evaluation within university settings. Built upon a sophisticated blend of cutting-edge technologies including Django, Python, HTML, CSS (SCSS), and JavaScript, UniTrack embodies a commitment to transparency, accountability, and ongoing enhancement across all facets of higher education institutions.

## Features

- **Secure Authentication**: UniTrack offers a secure login mechanism fortified by OTP verification, ensuring users, whether students or faculty, access the platform with confidence.
- **Intuitive Interface**: Users can seamlessly add reviews, selecting specific faculty or students, and augment evaluations with supporting documents through intuitive interfaces.
- **Customizable Review Categories**: Admins can tailor review categories, fostering a structured approach to assessment across various aspects such as teaching quality, learning resources, campus facilities, and administrative support.
- **Personalized Profiles**: Users have personalized profiles to monitor their performance within the university ecosystem, facilitating engagement and improvement.
- **Anonymous Feedback Collection**: UniTrack emphasizes anonymous feedback collection, enabling users to express opinions candidly, fostering honest and actionable insights.

## Installation

To install UniTrack, follow these steps:

1. Clone the repository:

```bash
    git clone https://github.com/your-username/unitrack.git
```

2. Navigate to the project directory:

```bash
    cd unitrack
``` 

3. Create a file named credentials.py in the root directory of the project, and add your credentials:


```bash
    auth_user = "your_email@example.com"
    auth_password = "your_email_password"
    db_name = "unitrack"
    host = "127.0.0.1"
```

4. Replace "your_email@example.com" with your email address and "your_email_password" with your email password.

5. Install dependencies:

```bash
    pip install -r requirements.txt
``` 

6. Run the Django server:

``` bash
    python manage.py runserver
```

### Access UniTrack in your web browser at http://127.0.0.1:8000/.



