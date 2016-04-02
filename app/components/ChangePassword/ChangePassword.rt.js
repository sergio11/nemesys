import React from 'react/addons';
import _ from 'lodash';
import ButtonInput from 'react-bootstrap/lib/ButtonInput';
import Alert from 'react-bootstrap/lib/Alert';
export default function () {
    return React.createElement('form', {
        'className': 'form',
        'onSubmit': this._onSubmit.bind(this)
    }, React.createElement('div', { 'className': 'header header-primary text-center' }, React.createElement('h4', {}, this.i18n.t('changepassword.title'))), React.createElement('div', { 'className': 'content' }, React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'email')), React.createElement('input', {
        'type': 'email',
        'name': 'email',
        'className': 'form-control',
        'placeholder': 'Email...',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'lock_outline')), React.createElement('input', {
        'type': 'password',
        'name': 'oldPassword',
        'placeholder': 'Old Password ...',
        'className': 'form-control',
        'onChange': this._onChange.bind(this)
    })), React.createElement('div', { 'className': 'input-group' }, React.createElement('span', { 'className': 'input-group-addon' }, React.createElement('span', { 'className': 'material-icons' }, 'lock_outline')), React.createElement('input', {
        'type': 'password',
        'name': 'newPassword',
        'placeholder': 'New Password ...',
        'className': 'form-control',
        'onChange': this._onChange.bind(this)
    }))), React.createElement('div', { 'className': 'footer text-center' }, React.createElement(ButtonInput, {
        'type': 'submit',
        'className': 'btn-raised',
        'value': this.i18n.t('changepassword.enter'),
        'bsStyle': 'primary'
    })), this.state.status == 'changed' ? React.createElement(Alert, { 'bsStyle': 'success' }, React.createElement('h4', {}, this.i18n.t('changepassword.success.title')), React.createElement('p', {}, this.i18n.t('changepassword.success.message'))) : null, this.state.status == 'nochanged' ? React.createElement(Alert, { 'bsStyle': 'danger' }, React.createElement('h4', {}, this.i18n.t('changepassword.error.title')), React.createElement('p', {}, this.i18n.t('changepassword.error.message'))) : null);
};