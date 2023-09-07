const chai = require('chai');
const chaiHttp = require('chai-http');
const server = require('../app'); // Import the server instance
const expect = chai.expect;

chai.use(chaiHttp);

describe('Simple Node.js Web App', () => {
    it('should return "Hello, World!" when accessing the root route', (done) => {
        chai.request(server) // Use the server instance for testing
            .get('/')
            .end((err, res) => {
                expect(res).to.have.status(200);
                expect(res.text).to.equal('Hello, World!');
                done();
            });
    });
});
