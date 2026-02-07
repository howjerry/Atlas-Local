// XSS via innerHTML: SHOULD trigger the rule
// Pattern: assignment to .innerHTML property
// NOTE: This is a test fixture for SAST rule validation

const userInput = req.body.content;

document.getElementById("output").innerHTML = userInput;

element.innerHTML = "<div>" + userData + "</div>";

container.innerHTML = buildHtmlFromInput(request.query.name);
