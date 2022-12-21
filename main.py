from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Table, Column, Integer, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
import os

# Learned how to host our code on a website on heroku or render. A lot to unpack here. First, create a git repo and push our code onto github.
# Make sure to include a requirements.txt so the 3rd party website knows what packages to install. Also, install gunicorn add a Procfile file and include
# web: gunicorn main:app. This well tell the 3rd party website to host through gunicorn and to direct them to our main.py file where our "app" is. In order
# to have a database on these websites, install psycopg2-binary b/c our database is running on postgres instead of sqlite.

# Use pip freeze > requirements.txt to create rquements page

# Big lesson today, the main things were creating a relational database and authorizing users on our site to have access to certain pages based on credentials
# Learned about hashing and salting passwords
# Created a decorated function that checked if the logged in user was the admin which is really cool
# Created relationships in our database that linked authors, blogs, and comments which is cool
# Learned about flash messages and how to show and stop showing certain elements of our page if our user was logged in such as the register/login/logout tabs
# using current_user.is_authenticated()



Base = declarative_base()

app = Flask(__name__)
app.app_context().push()

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "LMAO101")
app.config['WTF_CSRF_ENABLED'] = True
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///blog.db")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    # User can have many posts
    # Author and commenter refer to their linked properties in the other classes
    # Posts defines parent relationship with Blogpost, comments with Comment
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="commenter")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" refers to calling the tablename 'users'.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    author = relationship("User", back_populates="posts")

    # Establish a one to many relationship with blogpost and comments(1 blogpost can have multiple comments) just like we did with users and blogposts
    comments = relationship("Comment", back_populates="parent_post")

    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)

    # establishes relationship with User(parent)
    commenter_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    commenter = relationship("User", back_populates="comments")

    # establishes relationship with BlogPost(parent)
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates="comments")

    text = db.Column(db.String(500), nullable=False)



db.create_all()

#initalize the login manager
login_manager = LoginManager()
login_manager.init_app(app)


#very cool, make a wrapper that checks if the logged in ueser is the admin.
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #check if user is not admin
        try:
            if current_user.id != 1:
                return abort(403)
        except AttributeError:
            return abort(403)
        else:
            return f(*args, **kwargs)
    return decorated_function


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if register_form.validate_on_submit():
        email = register_form.email.data
        name = register_form.name.data

        if User.query.filter_by(email=email).first():
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        #generate hash and salted password
        password = generate_password_hash(register_form.password.data, method='pbkdf2:sha256', salt_length=8)

        new_user = User(email=email, password=password, name=name)
        db.session.add(new_user)
        db.session.commit()

        #log in and authenticate new user
        login_user(new_user)

        return redirect(url_for('get_all_posts'))

    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    login_form = LoginForm()
    if login_form.validate_on_submit():

        email = login_form.email.data
        password = login_form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email is not in our database, please try again or register!")
            return redirect(url_for('login'))

        elif not check_password_hash(user.password, password):
            flash("Wrong password, please try again!")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))


    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for('login'))

        new_comment = Comment(text=comment_form.comment.data, commenter=current_user, parent_post=requested_post)
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post, form=comment_form, current_user=current_user)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
