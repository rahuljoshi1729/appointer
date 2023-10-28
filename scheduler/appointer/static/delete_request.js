// Step 1: Retrieve the CSRF token from cookies
function getCSRFToken() {
    const cookies = document.cookie.split("; ");
    for (let cookie of cookies) {
        const [name, value] = cookie.split("=");
        if (name === "csrftoken") {
            return decodeURIComponent(value);
        }
    }
    return null;
}

// Step 2: Make the DELETE request with the CSRF token in headers
function makeDeleteRequest() {
    const userEmail = "user@example.com";  // Your user's email
    const doctorEmail = "doctor@example.com";  // Doctor's email for query parameters
    const csrfToken = getCSRFToken();

    if (csrfToken) {
        $.ajax({
            type: "DELETE",
            url: "/admin/delete?doctor_email=" + doctorEmail,
            headers: {
                "X-CSRFToken": csrfToken  // Include the CSRF token in headers
            },
            success: function(response) {
                // Handle the successful response
                console.log(response);
            },
            error: function(xhr, errmsg, err) {
                // Handle errors
                console.error(err);
            }
        });
    } else {
        console.error("CSRF token not found.");
    }
}

// Call the function to make the DELETE request
makeDeleteRequest();
