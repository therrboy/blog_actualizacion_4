from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, HiddenField, ValidationError
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField
from datetime import datetime


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    author_id = HiddenField(default=1, validators=[DataRequired()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    date = HiddenField(default=datetime.today().strftime('%B %d, %Y'))
    submit = SubmitField("Enter")


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Enter")


class Login(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Enter")


class CommentForm(FlaskForm):
    comment_text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")
