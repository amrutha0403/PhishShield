function submitForm() {
    document.getElementById("captchaForm").submit();
}

function captchaCallback() {
    submitForm();
}

function resetInput() {
    document.getElementById("basic-url").value = "";
}