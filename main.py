from flask import Flask, render_template, request, session, redirect,flash, current_app, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug import secure_filename
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import json
import os
import math
from datetime import datetime
from wtforms import Form, SubmitField,IntegerField,FloatField,StringField,TextAreaField, validators, PasswordField, ValidationError
from flask_wtf.file import FileField,FileRequired,FileAllowed
from flask_wtf import FlaskForm
from flask_msearch import Search
from flask_login import login_required, current_user, logout_user, login_user, LoginManager, UserMixin
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
from flask_migrate import Migrate
import secrets
import pdfkit
import stripe
with open('config.json', 'r')as c:
    params = json.load(c)["params"]
local_server = True
app = Flask(__name__)
app.secret_key = 'super-secret-key'
app.config['UPLOAD_FOLDER'] =params['upload_location']
app.config['UPLOADED_PHOTOS_DEST']=params['upload_paintings']
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
patch_request_class(app)
app.config.update(
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT= '465',
    MAIL_USE_SSL=True,
    MAIL_USERNAME = params['gmail-user'],
    MAIL_PASSWORD = params['gmail-password']

)
mail = Mail(app)
if(local_server):
    app.config['SQLALCHEMY_DATABASE_URI'] = params['local_uri']
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = params['prod_uri']

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
search = Search()
search.init_app(app)

migrate = Migrate(app, db)
with app.app_context ():
    if db.engine.url.drivername=="sqlite":
        migrate.init_app(app,db, render_as_batch=True)
    else:
        migrate.init_app(app, db)

app.config['publishable_key']=params['publishable_key']
app.config['stripe.api_key']=params['stripe_key']



login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view='customerLogin'
login_manager.needs_refresh_message_category='danger'
login_manager.login_message = "please login first"

class Contacts(db.Model):


    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    phone_num= db.Column(db.String(12),  nullable=False)
    msg = db.Column(db.String(80), nullable=False)
    date = db.Column(db.String(12), nullable=True)
    email = db.Column(db.String(20), nullable=False)

class Posts(db.Model):
    __searchable__=['name', 'description']


    id = db.Column(db.Integer, primary_key=True)
    title= db.Column(db.String(80), nullable=False)
    slug= db.Column(db.String(21),  nullable=False)
    price = db.Column(db.Numeric(10,2), nullable=False)
    discount = db.Column(db.Integer, default=0)
    description = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(12), nullable=True)
    img_file = db.Column(db.String(12), nullable=True)

class Addproducts(Form):
    id = IntegerField('Id' ,[validators.DataRequired()])
    title = StringField('Title',[validators.DataRequired()])
    slug = StringField('Slug',[validators.DataRequired()])
    price = FloatField('price',[validators.DataRequired()])
    discount = IntegerField('Discount', default=0)
    description = TextAreaField('Description', [validators.DataRequired()])
    img_file = FileField('img_file',validators=[FileRequired(), FileAllowed(['jpg', 'png','gif','jpeg'])])

#customer
class CustomerRegisterForm(FlaskForm):
    name = StringField('Name: ')
    username = StringField('Username: ', [validators.DataRequired()])
    email = StringField('Email: ', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password: ', [validators.DataRequired(),
                                            validators.EqualTo('confirm', message=' Both password must match! ')])
    confirm = PasswordField('Repeat Password: ', [validators.DataRequired()])
    country = StringField('Country: ', [validators.DataRequired()])
    state = StringField('State: ', [validators.DataRequired()])
    city = StringField('City: ', [validators.DataRequired()])
    contact = StringField('Contact: ', [validators.DataRequired()])
    address = StringField('Address: ', [validators.DataRequired()])
    zipcode = StringField('Zip code: ', [validators.DataRequired()])

    profile = FileField('Profile', validators=[FileAllowed(['jpg', 'png', 'jpeg', 'gif'], 'Image only please')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        if Register.query.filter_by(username=username.data).first():
            raise ValidationError("This username is already in use!")

    def validate_email(self, email):
        if Register.query.filter_by(email=email.data).first():
            raise ValidationError("This email address is already in use!")


class CustomerLoginForm(FlaskForm):
    email = StringField('Email: ', [validators.Email(), validators.DataRequired()])
    password = PasswordField('Password: ', [validators.DataRequired()])

@login_manager.user_loader
def user_loader(user_id):
    return Register.query.get(user_id)

class Register(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=False, nullable=False)

    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), unique=False, nullable=False)
    country = db.Column(db.String(200), unique=False, nullable=False)
    state= db.Column(db.String(200), unique=False, nullable=False)
    city = db.Column(db.String(200), unique=False, nullable=False)
    contact = db.Column(db.String(200), unique=False, nullable=False)
    address = db.Column(db.String(200), unique=False, nullable=False)
    zipcode = db.Column(db.String(200), unique=False, nullable=False)
    profile = db.Column(db.String(200), unique=False, nullable=False, default='profile.jpg')
    date_created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<Register %r>' %self.name
class JsonEcodedDict(db.TypeDecorator):
    impl = db.Text
    def process_bind_param(self, value, dialect):
        if value is None:
            return '{}'
        else:
            return json.dumps(value)
    def process_result_value(self, value, dialect):
        if value is None:
            return {}
        else:
            return json.loads(value)

class Customerorder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    invoice=db.Column(db.String(20), unique=True, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    customer_id = db.Column(db.Integer, unique=False, nullable=False)
    date_created= db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    orders = db.Column(JsonEcodedDict)

    def __repr__(self):
        return '<Customerorder %r>' %self.invoice

db.create_all()

@app.route("/")
def home():
    posts = Posts.query.filter_by().all()
    return render_template('index.html', params=params, posts=posts)
@app.route("/post", methods=['GET', 'post'])
def post():
    form = Addproducts(request.form)
    if request.method == 'POST':
        title = form.title.data
        slug = form.slug.data
        price = form.price.data
        discount = form.discount.data
        description = form.description.data
        img_file = photos.save(request.files.get('img_file'), name=secrets.token_hex(10) + ".")
        date = datetime.now()
        post = Posts(id=id, title=title, slug=slug, date=date, img_file=img_file, price=price, discount=discount
                     , description=description)
        db.session.add(post)
        flash(f'The product {title} was added in database', 'success')
        db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('post.html',params=params, form=form, title='add a product')


@app.route("/post/<string:post_slug>", methods=['GET'])
def post_route(post_slug):
    post = Posts.query.filter_by(slug=post_slug).first()

    return render_template('post.html', params=params, post = post )
@app.route("/post/<int:id>")
def single_page(id):
    post = Posts.query.get_or_404(id)
    return render_template('single_page.html', params=params, post = post )

@app.route('/result')
def result():
    searchword = request.args.get('q')
    post = Posts.query.msearch(searchword, fields=['title', 'description'], limit=6)
    return render_template('result.html', params=params, post=post)



@app.route("/about")
def about():
    return render_template('about.html', params=params)


@app.route("/artwork")
def artwork():
    posts = Posts.query.filter_by().all()
    last = math.ceil(len(posts) / int(params['no_of_posts']))
    page = request.args.get('page')
    if (not str(page).isnumeric()):
        page = 1
    page = int(page)
    posts = posts[(page - 1) * int(params['no_of_posts']):(page - 1) * int(params['no_of_posts']) + int(
        params['no_of_posts'])]
    if (page ==1):
        prev="#"
        next="/?page="+ str(page+1)
    elif(page==last):
        prev ="/?page="+ str(page-1)
        next ="#"
    else:
        prev = "/?page=" + str(page -1)
        next = "/?page="+ str(page+1)


    return render_template('artwork.html', params=params, posts=posts, prev=prev, next=next)

@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():

    if ('user' in session and session['user']== params['admin_user']):
        posts = Posts.query.all()
        return render_template('dashboard.html', params=params, posts=posts)

    if request.method=='POST':
        username = request.form.get('uname')
        userpass = request.form.get('pass')
        if (username == params['admin_user'] and userpass == params['admin_password']):
            #set the session vaiable
            session['user'] = username
            posts = Posts.query.all()
            return render_template('dashboard.html', params=params, posts= posts)
        #redirect to admin panel
    return render_template('login.html', params=params)


@app.route("/addpost", methods = ['GET', 'POST'])
def addpost():

    if ('user' in session and session['user'] == params['admin_user']):
        form = Addproducts(request.form)
        if request.method == 'POST':
            title = form.title.data
            slug = form.slug.data
            price = form.price.data
            discount = form.discount.data
            description = form.description.data
            date = datetime.now()
            img_file = photos.save(request.files.get('img_file'), name=secrets.token_hex(10) + ".")
            post = Posts(title=title, slug=slug, date=date, img_file=img_file, price=price, discount=discount
                         , description=description)
            db.session.add(post)
            flash(f'The product {title} was added in database', 'success')
            db.session.commit()
            return redirect('/dashboard')
        return render_template('addpost.html',params=params, form=form)




@app.route("/addpost/<int:id>", methods = ['GET', 'POST'])
def edit_post(id):
    if ('user' in session and session['user'] == params['admin_user']):
        if request.method == 'POST':
            box_title = request.form.get('title')
            slug = request.form.get('slug')
            price = request.form.get('price')
            discount = request.form.get('discount')
            description = request.form.get('description')
            img_file = request.form.get('img_file')
            date = datetime.now()
            if id=='0':
                post = Posts(title=box_title, slug=slug, date=date, img_file=img_file, price=price, discount=discount
                             , description=description)
                db.session.add(post)
                db.session.commit()
            else:
                post = Posts.query.filter_by(id=id).first()
                post.title = title
                post.slug = slug
                post.price = price
                post.discount = disconut
                post.description = description
                post.img_file = img_file
                post.date = date
                db.session.commit()
                return redirect('/edit_post/' +id)
        post= Posts.query.filter_by(id=id).first()
        return render_template('edit_post.html', params=params, post=post)


@app.route("/uploader/<int:id>", methods = ['GET', 'POST'])
def uploader(id):
    form =Addproducts(request.form)
    post = Posts.query.get_or_404(id)
    if (request.method == 'POST'):
        post.title= form.title.data
        post.slug = form.slug.data
        post.price = form.price.data
        post.discount = form.discount.data
        post.description = form.description.data

        if request.files.get('img_file'):
            try:
                os.unlink(os.path.join(current_app.root_path,"static/img/" + post.img_file))
                post.img_file = photos.save(request.files.get('img_file'), name=secrets.token_hex(10) + ".")
            except:
                post.img_file = photos.save(request.files.get('img_file'), name=secrets.token_hex(10) + ".")
        flash('the product was updated', 'success')
        db.session.commit()
        return redirect(url_for('dashbord'))
    form.title.data = post.title
    form.slug.data = post.slug
    form.price.data = post.price
    form.discount.data = post.discount
    form.description.data = post.description
    return render_template('addpost.html', params=params, form=form, title="update product", getpost=post)


@app.route("/logout")
def logout():
    session.pop('user')
    return redirect('/dashboard')

@app.route("/delete/<int:id>", methods = ['GET', 'POST'])
def delete(id):
    if ('user' in session and session['user'] == params['admin_user']):
        post = Posts.query.filter_by(id = id).first()
        if request.method == "POST":
            try:
                os.unlink(os.path.join(current_app.root_path, "static/img/" + post.img_file))
            except Exception as e:
                print(e)
        db.session.delete(post)
        db.session.commit()
        flash(f'the post {post.title} was delete from your record','success')
        return redirect(url_for('dashboard'))
    flash(f'can not delete the post ','success')
    return redirect('/dashboard')


@app.route("/contact", methods = ['GET', 'POST'])
def contact():
    if(request.method=='POST'):
        """DD ENTRY TO DATABASE"""
        name = request.form.get('name')
        email = request.form.get('email')
        phone= request.form.get('phone')
        message = request.form.get('message')
        entry = Contacts(name=name, phone_num= phone, date= datetime.now(), msg = message, email=email)
        db.session.add(entry)
        db.session.commit()
        mail.send_message('new message from ' + name,
                          sender=email,
                          recipients = [params['gmail-user']],
                          body = message + "\n" + phone
                          )
    return render_template('contact.html', params=params)

#customer registeration, login, logout
@app.route('/register', methods=['GET', 'POST'])
def customer_register():
    form = CustomerRegisterForm()
    if form.validate_on_submit():
        hash_password = bcrypt.generate_password_hash(form.password.data)
        register = Register(name=form.name.data, username=form.username.data, email=form.email.data,
                            password=hash_password, country=form.country.data, state=form.state.data, city=form.city.data,
                            contact=form.contact.data, address=form.address.data, zipcode=form.zipcode.data)
        db.session.add(register)
        flash(f'Welcome {form.name.data} Thank you for registering', 'success')
        db.session.commit()
        return redirect(url_for('customerLogin'))
    return render_template('register.html', form=form, params=params)




@app.route('/customer_login', methods=['GET', 'POST'])
def customerLogin():
    form = CustomerLoginForm()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('You are login now!', 'success')
            next = request.args.get('next')
            return redirect(next or url_for('home'))
        flash('Incorrect email or password', 'danger')
        return redirect(url_for('customerLogin'))

    return render_template('customer_login.html', form=form, params=params)


@app.route('/customer_logout')
def customer_logout():
    logout_user()
    return redirect('/')

#remove unwanted details from shopping cart
def updateshoppingcart():
    for key, shopping in session['Shoppingcart'].items():
        session.modified = True
        del shopping['image']
    return updateshoppingcart


@app.route('/getorder')
@login_required
def get_order():
    if current_user.is_authenticated:
        customer_id = current_user.id
        invoice = secrets.token_hex(5)
        updateshoppingcart
        try:
            order = Customerorder(invoice=invoice, customer_id=customer_id, orders=session['Shoppingcart'])
            db.session.add(order)
            db.session.commit()
            session.pop('Shoppingcart')
            flash('Your order has been sent successfully', 'success')
            return redirect(url_for('orders', invoice=invoice))
        except Exception as e:
            print(e)
            flash('Some thing went wrong while get order', 'danger')
            return redirect(url_for('carts'))


@app.route('/orders/<invoice>')
@login_required
def orders(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        customer = Register.query.filter_by(id=customer_id).first()
        orders = Customerorder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(
            Customerorder.id.desc()).first()
        for key, post in orders.orders.items():
            discount = (post['discount'] / 100) * float(post['price'])
            subTotal += float(post['price'])
            subTotal -= discount
            tax = ("%.2f" % (.06 * float(subTotal)))
            grandTotal = ("%.2f" % (1.06 * float(subTotal)))

    else:
        return redirect(url_for('customerLogin'))
    return render_template('orders.html', params=params, invoice=invoice, tax=tax, subTotal=subTotal, grandTotal=grandTotal,
                           customer=customer, orders=orders)



#cart
def MagerDicts(dict1, dict2):
    if isinstance(dict1, list) and isinstance(dict2, list):
        return dict1 + dict2
    elif isinstance(dict1, dict) and isinstance(dict2, dict):
        return dict(list(dict1.items()) + list(dict2.items()))
    return False


@app.route('/addcart', methods=['POST'])
def AddCart():
    try:
        post_id = request.form.get('post_id')
        post = Posts.query.filter_by(id=post_id).first()

        if post_id and request.method == "POST":
            DictItems = {post_id: {'title': post.title, 'price': float(post.price), 'discount': post.discount,'img_file': post.img_file,}}
            if 'Shoppingcart' in session:
                print(session['Shoppingcart'])
                if post_id in session['Shoppingcart']:
                    print("this product is in already in your cart")
                else:
                    session['Shoppingcart'] = MagerDicts(session['Shoppingcart'], DictItems)
                    return redirect(request.referrer)
            else:
                session['Shoppingcart'] = DictItems
                return redirect(request.referrer)

    except Exception as e:
        print(e)
    finally:
        return redirect(request.referrer)


@app.route('/carts')
def carts():
    if 'Shoppingcart' not in session or len(session['Shoppingcart']) <= 0:
        return redirect(request.referrer)
    subtotal = 0
    grandtotal = 0
    for key, product in session['Shoppingcart'].items():
        discount = (product['discount'] / 100) * float(product['price'])
        subtotal += float(product['price'])
        subtotal -= discount
        tax = ("%.2f" % (.06 * float(subtotal)))
        grandtotal = float("%.2f" % (1.06 * subtotal))
    return render_template('/carts.html', params=params, tax=tax, grandtotal=grandtotal)


@app.route('/updatecart/<int:code>', methods=['POST'])
def updatecart(code):
    if 'Shoppingcart' not in session or len(session['Shoppingcart']) <= 0:
        return redirect('/')
        try:
            session.modified = True
            for key, item in session['Shoppingcart'].items():
                if int(key)== code:
                    flash('Item is updated')
                    return redirect(url_for('carts'))
        except Exception as e:
            print(e)
            return redirect(url_for('carts'))
    if request.method == "POST":
        return redirect(url_for('carts'))


@app.route('/deleteitem/<int:id>')
def deleteitem(id):
    if 'Shoppingcart' not in session or len(session['Shoppingcart']) <= 0:
        return redirect('/')
    try:
        session.modified = True
        for key, item in session['Shoppingcart'].items():
            if int(key) == id:
                session['Shoppingcart'].pop(key, None)
                return redirect(url_for('carts'))
    except Exception as e:
        print(e)
        return redirect(url_for('carts'))


@app.route('/clearcart')
def clearcart():
    try:
        session.pop('Shoppingcart', None)
        return redirect('/')
    except Exception as e:
        print(e)



#customr/route.py
@app.route('/payment', methods=['POST'])
def payment():
    invoice = request.form.get('invoice')
    amount = request.form.get('amount')
    customer = stripe.Customer.create(
        email=request.form['stripeEmail'],
        source=request.form['stripeToken'],
    )
    charge = stripe.Charge.create(
        customer=customer.id,
        description='mayavee_arts',
        amount=amount,
        currency='usd',
    )
    orders = Customerorder.query.filter_by(customer_id=current_user.id, invoice=invoice).order_by(
        Customerorder.id.desc()).first()
    orders.status = 'Paid'
    db.session.commit()
    return redirect(url_for('thanks'))


@app.route('/thanks')
def thanks():
    return render_template('thanks.html')





@app.route('/get_pdf/<invoice>', methods=['POST'])
@login_required
def get_pdf(invoice):
    if current_user.is_authenticated:
        grandTotal = 0
        subTotal = 0
        customer_id = current_user.id
        if request.method == "POST":
            customer = Register.query.filter_by(id=customer_id).first()
            orders = Customerorder.query.filter_by(customer_id=customer_id, invoice=invoice).order_by(
                Customerorder.id.desc()).first()
            for _key, product in orders.orders.items():
                discount = (product['discount'] / 100) * float(product['price'])
                subTotal += float(product['price'])
                subTotal -= discount
                tax = ("%.2f" % (.06 * float(subTotal)))
                grandTotal = float("%.2f" % (1.06 * subTotal))

            rendered = render_template('pdf.html',params=params,invoice=invoice, tax=tax, grandTotal=grandTotal,
                                       customer=customer, orders=orders)
            pdf = pdfkit.from_string(rendered, False)
            response = make_response(pdf)
            response.headers['content-Type'] = 'application/pdf'
            response.headers['content-Disposition'] = 'inline; filename=' + invoice + '.pdf'
            return response
    return request(url_for('orders'))


app.run(debug=True)