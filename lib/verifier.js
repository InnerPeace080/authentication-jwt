const Debug = require('debug');
const debug = Debug('@feathersjs/authentication-jwt:verify');

class JWTVerifier {
  constructor (app, options = {}) {
    this.app = app;
    this.options = options;

    if (this.options.jwt && this.options.jwt.serviceByType) {
      this.serviceByType = {}
      Object.keys(this.options.jwt.serviceByType).forEach((key)=>{
        this.serviceByType[key] = (typeof this.options.jwt.serviceByType[key].service === 'string' ? app.service(this.options.jwt.serviceByType[key].service) : this.options.jwt.serviceByType[key].service);
      })
    }else{
      this.service = typeof options.service === 'string' ? app.service(options.service) : options.service;
    }
    if (!this.service && !this.serviceByType) {
      throw new Error(`options.service does not exist.\n\tMake sure you are passing a valid service path or service instance and it is initialized before @feathersjs/authentication-jwt.`);
    }

    this.verify = this.verify.bind(this);
  }

  verify (req, payload, done) {
    debug('Received JWT payload', payload);
    if (this.serviceByType && payload.type && this.serviceByType[payload.type] && this.options.jwt.serviceByType[payload.type]) {
      const id = payload[`${this.options.jwt.serviceByType[payload.type].entity}Id`];
      if (id === undefined) {
        debug(`JWT payload does not contain ${this.options.jwt.serviceByType[payload.type].entity}Id`);
        return done(null, {}, payload);
      }
      debug(`Looking up ${this.options.jwt.serviceByType[payload.type].entity} by id`, id);      
      this.serviceByType[payload.type].get(id).then(entity => {
        // const newPayload = { [`${this.options.jwt.serviceByType[payload.type].entity}Id`]: id };
        return done(null, entity, payload);
      })
      .catch(error => {
        debug(`Error populating ${this.options.jwt.serviceByType[payload.type].entity} with id ${id}`, error);
        return done(null, {}, payload);
      });
    }else{
      const id = payload[`${this.options.entity}Id`];
      if (id === undefined) {
        debug(`JWT payload does not contain ${this.options.entity}Id`);
        return done(null, {}, payload);
      }
      debug(`Looking up ${this.options.entity} by id`, id);
      this.service.get(id).then(entity => {
        // const newPayload = { [`${this.options.entity}Id`]: id };
        return done(null, entity, payload);
      })
      .catch(error => {
        debug(`Error populating ${this.options.entity} with id ${id}`, error);
        return done(null, {}, payload);
      });
    }
  }
}

module.exports = JWTVerifier;
