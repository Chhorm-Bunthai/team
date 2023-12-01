const User = require('./../models/userSchema');

exports.signUp = async(req, res) => {
    try{
        const newUser = await User.create({
            name: req.body.name,
            email: req.body.email,
            password: req.body.password,
            passwordConfirm: req.body.passwordConfirm
        });
        res.status(200).json({
            status: 'success',
            data: {
                user: newUser
            }
        })
    }catch(err){
        res.status(404).json(`${err}`);
    };
}