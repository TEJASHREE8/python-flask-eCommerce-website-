def validate_username(self, username):
    if Register.query.filter_by(username=username.data).first():
        raise ValidationError("This username is already in use!")

def validate_email(self, email):
    if Register.query.filter_by(email=email.data).first():
        raise ValidationError("This email address is already in use!")

@login_manager.user_loader
def user_loader(user_id):
    return Register.query.get(user_id)


@app.route('/customer_login', methods=['GET', 'POST'])
def customerLogin():
    form = CustomerLoginFrom()
    if form.validate_on_submit():
        user = Register.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('You are login now!', 'success')
            next = request.args.get('next')
            return redirect(next or ('/')
         flash('Incorrect email or password', 'danger')
         return redirect(url_for('customerLogin'))

     return render_template('customer_login.html', form=form, params=params)




