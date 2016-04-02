import React from 'react/addons';
import _ from 'lodash';
import Input from 'react-bootstrap/lib/Input';
import ButtonInput from 'react-bootstrap/lib/ButtonInput';
import Glyphicon from 'react-bootstrap/lib/Glyphicon';
import Alert from 'react-bootstrap/lib/Alert';
import DatePicker from 'react-bootstrap-date-picker';
export default function () {
    return React.createElement('form', {
        'className': 'form',
        'onSubmit': this._createUser.bind(this)
    }, React.createElement('div', { 'className': 'header header-primary text-center' }, React.createElement('h4', {}, this.i18n.t('signup.title')), React.createElement('div', { 'className': 'social-line' }, React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-facebook-square' })), React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-twitter' })), React.createElement('a', {
        'href': '#',
        'className': 'btn btn-just-icon'
    }, React.createElement('span', { 'className': 'fa fa-google-plus' })))), React.createElement('p', { 'className': 'text-divider' }, this.i18n.t('signup.other')), React.createElement('div', { 'className': 'content' }, React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'face')), React.createElement('input', {
        'type': 'text',
        'name': 'firstname',
        'className': 'form-control',
        'placeholder': 'First Name ...',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'face')), React.createElement('input', {
        'type': 'text',
        'name': 'lastname',
        'className': 'form-control',
        'placeholder': 'Last Name ...',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'email')), React.createElement('input', {
        'type': 'email',
        'name': 'email',
        'className': 'form-control',
        'placeholder': 'Email...',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'date')), React.createElement(DatePicker, {
        'name': 'birthday',
        'placeholder': 'Birthday ...',
        'value': this.state.birthday,
        'onChange': this._onChange.bind(this),
        'calendarPlacement': 'top'
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'lock_outline')), React.createElement('input', {
        'type': 'password',
        'name': 'password',
        'placeholder': 'Password...',
        'className': 'form-control',
        'onChange': this._onChange.bind(this)
    }))), React.createElement('div', { 'className': 'footer text-center' }, React.createElement(ButtonInput, {
        'type': 'submit',
        'className': 'btn-raised',
        'value': this.i18n.t('signup.submit'),
        'bsStyle': 'primary'
    })));
};