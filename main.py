from flask import Flask, render_template, redirect, url_for, flash, session, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, Login, CommentForm
from flask_gravatar import Gravatar
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(20), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    posts = relationship("BlogPost", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"

    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(50), unique=True, nullable=False)
    subtitle = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(300), nullable=False)

    author_id = db.Column("user_id", db.Integer, db.ForeignKey("users.id"))
    comments = relationship("Comment", back_populates="post")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    post = relationship("BlogPost", back_populates="comments")
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    user = relationship("User")


"""
if not os.path.isfile('sqlite:///blog.db'):
    with app.app_context():
        db.create_all()

with app.app_context():
    admin_user = User(
        email='administrador@correo.com',
        password=generate_password_hash('12345678'),
        name='Admin',
        is_admin=True
    )
    db.session.add(admin_user)
    db.session.commit()
"""

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=session.get('logged_in', False))


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data

        if User.query.filter_by(email=email).first():
            flash('Ese correo electrónico ya existe, si es tuyo ingresa.')
            return redirect(url_for('login'))

        else:
            password = form.password.data

            if len(password) < 8:
                flash('El password debe tener al menos 8 caracteres.')
                return redirect(url_for('register'))

            hash_and_salted_password = generate_password_hash(
                password,
                method='pbkdf2:sha256',
                salt_length=8
            )

            new_user = User(
                email=email,
                password=hash_and_salted_password,
                name=form.name.data
            )

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            session[
                'logged_in'] = True

            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = Login()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(
            email=email).first()

        if not user:
            flash('Error: Has introducido un correo electrónico incorrecto')
            return redirect(url_for('login'))

        if not check_password_hash(user.password, password):
            flash('Error: Has introducido una contraseña incorrecta')
            return redirect(url_for('login'))

        login_user(user)
        session[
            'logged_in'] = True
        return redirect(url_for('get_all_posts'))

    session.pop('logged_in', None)
    return render_template('login.html', logged_in=current_user.is_authenticated, form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.session.get(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        new_comment = Comment(
            text=form.comment_text.data,
            post=requested_post,
            user=current_user
        )

        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    comments = Comment.query.filter_by(post=requested_post).all()

    return render_template("post.html", post=requested_post, form=form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@login_required
def add_new_post():
    author = db.session.query(User).get(current_user.id)
    user_id = int(current_user.get_id())
    print(author)
    print(user_id)
    form = CreatePostForm()

    if not current_user.is_admin:
        abort(403)

    print("Formulario recibido:", form.data)

    if form.validate_on_submit():
        print("El formulario es válido.")
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            date=form.date.data or datetime.today().strftime('%B %d, %Y'),
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=user_id
        )
        print("Datos del formulario antes de agregar el nuevo post:", form.data)

        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    else:
        print("El formulario no es válido.")
        print("Errores del formulario:", form.errors)

    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@login_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author_id,
        body=post.body
    )
    if not current_user.is_admin:
        abort(403)

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author_id.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    if post_to_delete:
        Comment.query.filter_by(post_id=post_id).delete()

        db.session.delete(post_to_delete)
        db.session.commit()
        return redirect(url_for("get_all_posts"))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
