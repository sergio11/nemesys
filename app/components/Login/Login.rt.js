import React from 'react/addons';
import _ from 'lodash';
import Grid from 'react-bootstrap/lib/Grid';
import Row from 'react-bootstrap/lib/Row';
import Col from 'react-bootstrap/lib/Col';
import Input from 'react-bootstrap/lib/Input';
import ButtonInput from 'react-bootstrap/lib/ButtonInput';
import Glyphicon from 'react-bootstrap/lib/Glyphicon';
import Alert from 'react-bootstrap/lib/Alert';
function scopeMessage1() {
    var message = this._authError(this.state.error);
    return React.createElement(Alert, { 'bsStyle': 'danger' }, React.createElement('h4', {}, this.i18n.t('login.fail_title')), React.createElement('p', {}, message));
}
export default function () {
    return React.createElement('div', { 'className': 'signup-page' }, React.createElement('div', { 'className': 'wrapper' }, React.createElement('div', {
        'className': 'header header-filter',
        'style': {
            backgroundImage: 'url(\'./img/city.jpg\')',
            backgroundSize: 'cover',
            backgroundPosition: 'top center'
        }
    }, React.createElement(Grid, {}, React.createElement(Row, {}, React.createElement(Col, {
        'md': 4,
        'mdOffset': 4,
        'sm': 6,
        'smOffset': 3
    }, React.createElement('div', { 'className': 'card card-signup' }, React.createElement('form', {
        'className': 'form',
        'onSubmit': this._onSubmit.bind(this)
    }, React.createElement('div', { 'className': 'header header-primary text-center' }, React.createElement('h4', {}, this.i18n.t('login.title')), React.createElement('div', { 'className': 'social-line' }, React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-facebook-square' })), React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-twitter' })), React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-google-plus' })))), React.createElement('p', { 'className': 'text-divider' }, this.i18n.t('login.other')), React.createElement('div', { 'className': 'content' }, React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'email')), React.createElement('input', {
        'type': 'email',
        'name': 'email',
        'className': 'form-control',
        'placeholder': 'Email...',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'lock_outline')), React.createElement('input', {
        'type': 'password',
        'name': 'password',
        'placeholder': 'Password...',
        'className': 'form-control',
        'onChange': this._onChange.bind(this)
    }))), React.createElement('div', { 'className': 'footer text-center' }, React.createElement(ButtonInput, {
        'type': 'submit',
        'className': 'btn-raised',
        'value': this.i18n.t('login.enter'),
        'bsStyle': 'primary'
    }))))), React.createElement(Col, {
        'xs': 8,
        'smOffset': 2
    }, this.state.authFail ? scopeMessage1.apply(this, []) : null))))));
};