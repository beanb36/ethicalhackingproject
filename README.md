# Ethical Hacking Project
> This is our Ethical Hacking final group project. Our goal is to create a keylogger _detection_ tool that monitors for suspicious processes on a computer. This will be a python script running on the computer. It will monitor suspicious actions that are common with keyloggers.

- Frequent write actions
- Increased action logging
- Keyboard related APIs? _maybe_
- Action context 

# What can I work on today?

Here are a few areas we'll need to work on to get started. 

- Importing running processes
- Sorting running processes by risk
- Context-based analysis

  If something is running for 30 seconds, it is probably fine. 
  If something is running for 6 hours straight, it should be marked suspicious. etc. 
- Automatically prompting the user to stop running threats
- A UI that notifies the user of potential threats

# How is this different from typical tools?

We won't just be looking at signature data, but complex context data. We will analyze and return actual reason-based errors. 

This type of typical endpoint analysis gives unactionable errors and reasoning. Our system will take data and give an actual reason for the flag, instead of an unrespondable error code. 
