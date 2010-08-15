function checkField(el, val) {
    if (el.value === "")
        el.value = val;
    else if (el.value === val)
        el.value = '';
}
function checkPasswordField(el, val) {
    if (el.value === "") {
        el.value = val;
        el.type = 'textfield';
    }
    else if (el.value === val) {
        el.value = '';
        el.type = 'password';
    }
}
