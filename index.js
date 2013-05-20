var pwd = require('pwd');

module.exports = function (schema) {
  schema.add({
    __password: {
      hash: {type: String, required: true},
      salt: {type: String, required: true}
    }
  });

  schema.statics.signin = function (email, password, done) {
    this.findOne({email: email}, function (err, user) {
      if (err) return done(err);
      
      if (!user) return done(new Error('User not found'));

      user.authenticate(password, function (err) {
        if (err) return done(err);

        done(null, user);
      });
    });
  };

  schema.methods.setPassword = function (password, done) {
    var user = this;

    pwd.hash(password, function (err, salt, hash) {
     if (err) return done(err);

      user.set({
	  __password: { salt: salt, hash: hash}
      });      

      done(err);
    });    
  };

  schema.methods.authenticate = function (submittedPassword, done) {
    var user = this;
    var hashed = user.get('__password');

    pwd.hash(submittedPassword, hashed.salt, function (err, hash) {
      if (err) return done(err);

      if (hashed.hash == hash) {
        return done(null);
      }

      done(new Error('Invalid Credentials'));
    });
  };
};
