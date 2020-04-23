const sdk = require("miniprogram-taas-sdk");





function sayHello() {
    console.log(`Hello !`)
}
function sayGoodbye(name) {
    console.log(`Goodbye ${name} !`)
}

module.exports.sayHello = sayHello
exports.sayGoodbye = sayGoodbye
