# Telstra_Spring4Shell_Cybersecurity-Simulation
Telstra Cybersecurity Simulation featuring Spring4Shell Zero-Day Vulnerability and SOC playbook to investigation and attack mitigation.

Link to the simulation: https://www.theforage.com/virtual-internships/RNhbu8QnDzthwynEf

---

### INTRO

In March 2022, a critical zero-day vulnerability was disclosed in the popular Spring Framework—an open-source platform widely used by Java developers to build modern web applications. This vulnerability, now known as Spring4Shell, was assigned the identifier CVE-2022-22965.

Spring4Shell allows an attacker to remotely execute arbitrary code on servers running vulnerable versions of Spring, potentially giving them full control over affected systems. This type of attack is known as Remote Code Execution (RCE)—one of the most severe and dangerous types of vulnerabilities in cybersecurity.

What made Spring4Shell particularly alarming was:

- It could be exploited without authentication, meaning attackers didn't need to log in or bypass credentials.

- It affected a core component of the Spring framework, used by countless enterprise applications.

- It resembled Log4Shell, another major zero-day that had made headlines only a few months earlier.

Spring4Shell highlights the risk of vulnerabilities in widely adopted frameworks. When core development tools are affected, thousands of applications become potential attack vectors overnight.

---

### Task 1 - Responding to a Malware Attack

### Summary:
You are an information security analyst in the Security Operations Centre. A common task and responsibility of information security analysts in the SOC is to respond to triage incoming threats and respond appropriately, by notifying the correct team depending on the severity of the threat. It’s important to be able to communicate the severity of the incident to the right person so that the organisation can come together in times of attack.

### The Task:
Your task is to triage the current malware threat and figure out which infrastructure is affected.
First, find out which key infrastructure is currently under attack. Note the priority of the affected infrastructure to the company - this will determine who is the respective team to notify.
After, draft an email to the respective team alerting them of the current attack so that they can begin an incident response. Make sure to include the timestamp of when the incident occurred. Make it concise and contextual.
The purpose of this email is to ensure the respective team is aware of the ongoing incident and to be prepared for mitigation advice.

### File: Task-1_Telstra-SOC-email-draft.docx (https://github.com/Mi117/Telstra_Spring4Shell_Cybersecurity-Simulation/blob/main/Task-1_Telstra-SOC-email-draft.docx)

---

### Task 2 - Analysing the Attack

### Summary:
Now that you have notified the infrastructure owner of the current attack, analyse the firewall logs to find the pattern in the attacker’s network requests. You won’t be able to simply block IP addresses, because of the distributed nature of the attack, but maybe there is another characteristic of the request that is easy to block.

An important responsibility of an information security analyst is the ability to work across disciplines with multiple teams, both technical and non-technical.

### The Task:
1. Analyse the firewall logs in the resources section.

2. Identify what characteristics of the Spring4Shell vulnerability have been used.

3.  Draft an email to the networks team with your findings. Make sure to be concise, so that they can develop the firewall rule to mitigate the attack. You can assume the recipient is technical and has dealt with these types of requests before.

### File: Task-2_Firewall-Reqwuest-email.docx

---

### Task 3 - Mitigate the Malware Attack 

### Summary:
Work with the networks team to implement a firewall rule using the Python scripting language. Python is a common scripting language used across both offensive and defensive information security tasks.

In this task, we will simulate the firewall’s scripting language by using an HTTP Server. You can assume this HTTP Server has no computational requirements and has the sole purpose of filtering incoming traffic.

### The Task: 
Use Python to develop a firewall rule to mitigate the attack. Develop this rule in `firewall_server.py` and only upload this file back here.

### File: Task-3_Firewall_server.py

---

### Task 4 - Incident Postmortem

### Summary: 
After an incident has occurred, it’s best practice to document and record what has happened. A common report written after an incident is a postmortem, which covers a timeline of what has occurred, who was involved in responding to the incident, a root cause analysis and any actions which have taken place.

The purpose of the postmortem is to provide a ‘paper trail’ of what happened, which may be used in future governance, risk, or compliance audits, but also to educate the team on what went down, especially for those on the team who weren’t involved

### The Task:
For this task, create an incident postmortem of the malware attack, covering the details you have picked up in the previous tasks.

Make sure to include when the incident started and the root cause. Remember, the more detail the better.

### File: Task-4_Malware-Attack_Postmortem.docx

---


### CONCLUSIONS

The Spring4Shell era taught the cybersecurity community that our most fundamental assumptions about application security needed updating. We learned that widely-trusted software components could become weapons, that zero-day vulnerabilities could have immediate global impact, and that traditional security controls had significant blind spots.
More importantly, we learned that effective zero-day response requires a combination of technical capabilities, organizational preparedness, and human expertise that many organizations are still developing.

Most importantly I want to thank @Forage and @Telstra for the brilliant simulation as I’m grateful for opportunities like this to sharpen my skills and stay updated on threats in the field. Highly recommend this simulation for anyone exploring cybersecurity or interested in threat response.

#CyberSecurity #Spring4Shell #ZeroDay #Telstra #Forage #Infosec #SecurityAwareness #LearningByDoing #DigitalSecurity
