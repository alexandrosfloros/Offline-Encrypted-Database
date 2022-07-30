# Motivation

This project was originally made for personal use to securely store sensitive information locally behind a login system, across one or more user accounts.

# Features

Main features:

* Ability to register multiple accounts to store data
* Ability to change password upon logging in

Other features:

* Secure password verification using ``sha256``
* Secure encryption algorithm based on the password
* Robust to problematic inputs

# How to use

## Execution

The file used to run the project is ``main.py``.

## Accounts

An account can be created by selecting an appropriate username and password, and clicking on the "Register" button. Upon registering, the user will be logged in and able to access their account's interface. Alternatively, they may login to an existing account by inserting the right credentials and clicking on the "Login" button.

## Interface

When logged in, the user can write text in the text box provided and, when done, they can save and quit by clicking on the "Save and Logout" button. Alternatively, they may quit without saving any changes by simply clicking on the "Logout" button. The password can be changed by inserting the new password in the field provided and clicking on the "Change" button.
