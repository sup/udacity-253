#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import hashlib
import os
import jinja2
import webapp2
import urlparse
import re
import random
import string
import urllib2
from xml.dom import minidom
import json
import logging
import time
from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#== GLOBAL VARIABLES ====================================================
USER_REGEX = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_REGEX = re.compile(r"^.{3,20}$")
EMAIL_REGEX = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"

#== HTML DOCUMENTS ======================================================
date_form = """
<form method="post">
    What is your birthday?
    <br>
    <label>
        Month 
        <input type="text" name="month" value="%(month)s">
    </label>
    <label>
        Day 
        <input type="text" name="day" value="%(day)s">
    </label>
    <label>
        Year
        <input type="text" name="year" value="%(year)s">
    </label>
    <div style="color: red">%(error)s</div>
    <br>
    <br>
    <input type="submit">
</form>
"""

rot13_form = """
<h2> Enter some text to ROT13: </h2>
<form method="post">
    <textarea name="text" value="%(message)s" style="height:100px; width: 400px;">%(message)s</textarea>
    <br>
    <input type="submit">
</form>
"""

signup_form = """
<h2> Signup </h2>
<form method="post">
    <table>
        <tbody>
            <tr>
                <td class="label">Username</td>
                <td>
                    <input type="text" name="username" value="%(username)s">
                </td>
                <td class="error" style="color:red">%(user_error)s<td>
            </tr>
            <tr>
                <td class="label">Password</td>
                <td>
                    <input type="password" name="password" value="%(password)s">
                </td>
                <td class="error" style="color:red">%(pass_error)s<td>
            </tr>
            <tr>
                <td class="label">Verify Password</td>
                <td>
                    <input type="password" name="verify" value="%(verify)s">
                </td>
                <td class="error" style="color:red">%(verify_error)s<td>
            </tr>
            <tr>
                <td class="label">Email (optional)</td>
                <td>
                    <input type="text" name="email" value="%(email)s">
                </td>
                <td class="error" style="color:red">%(email_error)s<td>
            </tr>
        </tbody>
    </table>
    <input type="submit">
</form>
"""

#== Global Handler (Jinja2 Templates) ====================================
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


#== Unit 2 ===============================================================
class DateHandler(webapp2.RequestHandler):
    def write_date_form(self, error="", month="", day="", year=""):
        self.response.write(date_form % {"error": error,
                                    "month": escape_html(month),
                                    "day": escape_html(day),
                                    "year": escape_html(year)})

    def get(self):
        #self.response.headers['Content-Type'] = 'text/plain'
        self.write_date_form()

    def post(self):
        user_month = self.request.get('month')
        user_day = self.request.get('day')
        user_year = self.request.get('year')

        month = valid_month(user_month)
        day = valid_day(user_day)
        year = valid_year(user_year)

        if not (month and day and year):
            self.write_date_form("That doesn't look like a valid date.", user_month, user_day, user_year)
        else:
            self.redirect("/thanks")


class ThanksHandler(webapp2.RequestHandler):
    def get(self):
        self.response.write("Thanks! That's a valid date!")


#== PROBLEM SET 2 ========================================================
class Rot13Handler(webapp2.RequestHandler):
    def write_rot13_form(self, message=""):
        self.response.write(rot13_form % {'message': message})

    def get(self):
        self.write_rot13_form()

    def post(self):
        message = self.request.get('text')
        message = caeser(message, 13)
        #Escape HTML Characters
        message = escape_html(message)
        self.write_rot13_form(message)

#== PROBLEM SET 2/4 =======================================================
class SignUpHandler(Handler):
    #Method for rendering form using Python string substitution
    def write_signup_form(self, username="", email="", user_error="", pass_error="", verify_error="", email_error=""):
        self.response.write(signup_form % {"username":username,
                                        "password":"",
                                        "verify":"",
                                        "email":email,
                                        "user_error":user_error,
                                        "pass_error":pass_error,
                                        "verify_error":verify_error,
                                        "email_error":email_error})

    #Method for rendering form using a template
    def render_form(self, username="", email="", user_error="", pass_error="", verify_error="", email_error=""):
        self.render("signup.html", username=username, password="", verify="", email=email,
                    user_error=user_error, pass_error=pass_error, verify_error=verify_error, 
                    email_error=email_error)

    def get(self):
        self.render_form()

    def post(self):
        #Raw input data
        user_username = self.request.get('username')
        user_password = self.request.get('password')
        user_verify = self.request.get('verify')
        user_email = self.request.get('email')

        #Test if the input data are valid
        username = valid_username(user_username)
        password = valid_password(user_password)
        verify = valid_verify(user_password, user_verify)
        email = valid_email(user_email)

        #If the email field is blank, then it's valid
        if user_email == "":
            email = True

        #Initialize error statements
        USER_ERROR = ""
        PASS_ERROR = ""
        VERIFY_ERROR = ""
        EMAIL_ERROR = ""

        #Discrete system for each error
        if not username:
            USER_ERROR = "That's not a valid username."
        if not verify:
            VERIFY_ERROR = "The passwords don't match."
        if not password:
            VERIFY_ERROR = ""
            PASS_ERROR = "That's not a valid password."
        if not email:
            EMAIL_ERROR = "That's not a valid email."

        #If an error exists, rewrite the form for the user
        if not (username and verify and password and email):
            self.render_form(user_username, user_email, USER_ERROR, PASS_ERROR, VERIFY_ERROR, EMAIL_ERROR)

        #Else, redirect to the welcome and set a browser cookie
        elif username and verify and password and email:
            new_user = User.all().filter("username", user_username).get()
            print new_user
            if new_user == None:
                hashed_pw = make_pw_hash(str(user_username), str(user_password))
                user = User(username = user_username, password = hashed_pw, email = user_email)
                user.put()
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'username=%s;Path=/' % str(user_username))
                self.redirect("/blog/welcome")
            else:
                USER_ERROR = "That user already exists."
                self.render_form(user_username, user_email, USER_ERROR, PASS_ERROR, VERIFY_ERROR, EMAIL_ERROR)


class WelcomeHandler(Handler):
    def get(self):
        self.response.headers['Content-Type'] = 'text/plain'
        username = self.request.cookies.get('username')
        #If the username parameter is changed to be invalid, redirect
        if not valid_username(username):
            self.redirect("/blog/signup")
        self.write("Welcome, " + username + "!")


class LoginHandler(Handler):
    def render_form(self, username="", login_error=""):
        self.render("login.html", username=username, password="", login_error=login_error)

    def get(self):
        self.render_form()

    def post(self):
        login_error = "Either the username or password is incorrect."
        username = self.request.get('username')
        password = self.request.get('password')
        current_user = User.all().filter("username", username).get()
        if current_user == None:
            self.render_form(username, login_error)
        else:
            password_hash = current_user.password
            print password_hash
            if valid_pw(username, password, password_hash):
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.headers.add_header('Set-Cookie', 'username=%s;Path=/' % str(username))
                self.redirect("/blog/welcome")
                print "redirected to welcome"
            else:
                self.render_form(username, login_error)


class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'username=;Path=/')
        self.redirect("/blog/signup")


class User(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty(required = False)


#== ASCII CHAN ===========================================================
def top_arts(update = False):
    key = "top"
    arts = memcache.get(key)
    if arts is None or update:
        print "DB QUERY"
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC LIMIT 10")
        #Cache the query so we don't keep running them
        arts = list(arts)
        memcache.set(key, arts)
    return arts

class AsciiHandler(Handler):
    def render_front(self, title="", art="", error=""):
        arts = top_arts()
        #Find which arts have coordinates. If any, make an image url
        points = filter(None, (a.coords for a in arts))
        img_url = None
        if points:
            img_url = gmaps_img(points)
        #Display the image url
        self.render("front.html", title=title, art=art, error=error, arts=arts, img_url=img_url)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(title = title, art = art)
            #Lookup user coordinates from IP and add them to the art
            coords = get_coords(self.request.remote_addr)
            if coords:
                a.coords = coords
            a.put()
            time.sleep(.5)
            top_arts(True)
            self.redirect("/ascii")
        else:
            error = "you need to post both a title and art!"
            self.render_front(title, art, error)


class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty(required = False)


#== PROBLEM SET 3 BLOG ===================================================
class BlogHandler(Handler):
    """
    Handler for displaying the front page of the blog
    """
    def render_blog(self):
        posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC")
        self.render("blog.html", posts=posts)

    def get(self):
        self.render_blog()


class PageHandler(Handler):
    """
    Handler for displaying unique pages for each blog post
    """
    def render_post(self, post=""):
        posts = [post]
        self.render("blog.html", posts=posts)

    def get(self, post_id):
        post_key = db.Key.from_path('BlogPost', int(post_id))
        post = db.get(post_key)
        self.render_post(post)


class NewPostHandler(Handler):
    """
    Handler for working with new post form to create new blog posts
    """
    def render_form(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject, content=content, error=error)

    def get(self):
        self.render_form()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            bp = BlogPost(subject = subject, content = content)
            bp.put()
            self.redirect('/blog/%s' % str(bp.key().id()))
        else:
            error = "You need both a subject and some content."
            self.render_form(subject, content, error)

class BlogPost(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

#== PROBLEM SET 5 ========================================================
class JSONHandler(Handler):
    def get(self, post_id):
        self.response.headers["Content-Type"] = "application/json; charset=UTF-8"
        if post_id:
            output = {}
            p = BlogPost.get_by_id(int(post_id))
            output.update({"subject":p.subject,"content":p.content,"created":p.created.strftime("%b %d, %Y")})
        else:
            output = []
            posts = db.GqlQuery("Select * From BlogPost Order By created DESC")
            for p in posts:
                output.append({"subject":p.subject,"content":p.content,"created":p.created.strftime("%b %d, %Y")})
        self.write(json.dumps(output))


#== MAIN APPLICATION =====================================================
app = webapp2.WSGIApplication([
    ('/', DateHandler),
    ('/thanks', ThanksHandler),
    ('/rot13', Rot13Handler),
    ('/blog/signup', SignUpHandler),
    ('/blog/welcome', WelcomeHandler),
    ('/ascii', AsciiHandler),
    ('/blog', BlogHandler),
    ('/blog/newpost', NewPostHandler),
    ('/blog/([0-9]+)', PageHandler),
    ('/blog/login', LoginHandler),
    ('/blog/logout', LogoutHandler),
    ('/blog/([0-9]*).json+',JSONHandler)
], debug=True)

#== Helper Functions/Data ================================================

#FOR DATES
months = ['January',
          'February',
          'March',
          'April',
          'May',
          'June',
          'July',
          'August',
          'September',
          'October',
          'November',
          'December']

def valid_day(day):
    if day:
        try:
            i = int(day)
            if i >= 1 and i <= 31:
                return i
            else:
                return None
        except Exception:
            return None
          
def valid_month(month):
    try:
        i = months.index(month.lower().capitalize())
        return months[i]
    except Exception:
        return None

def valid_year(year):
    if year:
        try:
            y = int(year)
            if y >= 1900 and y <= 2020:
                return y
        except Exception:
            return None

#FOR ESCAPING HTML
def escape_html(s):
    """
    Returns: Original string with escaped html characters.
    """
    for (i,o) in (("&", "&amp;"),
                (">", "&gt;"),
                ("<", "&lt;"),
                ('"', "&quot;")):
        s = s.replace(i,o)
    return s

#FOR ROT13
def caeser(message, key):
    """
    Returns: Ciphertext of message encrypted with a Caeser cipher. This
    encryption function preserves case, whitespace, and punctuation.
    """
    #Raw Alphabets
    low_alpha = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
                 "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" ]

    cap_alpha = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
                 "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" ]

    #Dictionaries for each alphabet type
    low_dict = {}
    cap_dict = {}
    for i in range(26):
        low_dict[low_alpha[i]] = low_alpha[(i+key) % 26]
        cap_dict[cap_alpha[i]] = cap_alpha[(i+key) % 26]

    #Conversion of message to ciphertext
    ciphertext = ""
    for l in message:
        if l in low_dict:
            l = low_dict[l]
        if l in cap_dict:
            l = cap_dict[l]
        ciphertext += l

    return ciphertext

#FOR SIGNUP
def valid_username(username):
    """
    Returns: True if the username is valid, else False.
    """
    return USER_REGEX.match(username)

def valid_password(password):
    """
    Returns: True if the password is valid, else False.
    """
    return PASS_REGEX.match(password)

def valid_email(email):
    """
    Returns: True if the email is valid, else False.
    """
    return EMAIL_REGEX.match(email)

def valid_verify(password,verify):
    """
    Returns: True if the passwords match, else False.
    """
    return password == verify

#For hashing/security (naive)
def hash_str(s):
    return hashlib.md5(s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split("|")[0]
    if h == make_secure_val(val):
        return val

def make_salt(size = 5, char = string.letters):
    return ''.join(random.choice(char) for x in xrange(size))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    return hashlib.sha256(name + pw + salt).hexdigest() + "," + salt

def valid_pw(name, pw, h):
    salt = h.split(",")[1]
    return h == hashlib.sha256(name + pw + salt).hexdigest() + "," + salt

#For geolocation API
def get_coords(ip):
    BASE_URL = "http://api.hostip.info/?ip="
    url = BASE_URL + ip
    content = None
    try:
        content = urllib2.urlopen(url).read()
    except URLError:
        return

    if content:
        #Parse the XML and find the coordinates
        xml = minidom.parseString(content)
        coords = xml.getElementsByTagName("gml:coordinates")
        if coords and coords[0].childNodes[0].nodeValue:
            lon, lat = coords[0].childNodes[0].nodeValue.split(",")
            return db.GeoPt(lat, lon)

def gmaps_img(points):
    markers = "&".join("markers=%s,%s" % (p.lat, p.lon) for p in points)
    return GMAPS_URL + markers



