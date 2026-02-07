// XSS via innerHTML: should NOT trigger the rule
// Uses safe alternatives like textContent or sanitized HTML

const userInput = req.body.content;

document.getElementById("output").textContent = userInput;

element.innerText = userData;

const node = document.createElement("div");
node.appendChild(document.createTextNode(userInput));
