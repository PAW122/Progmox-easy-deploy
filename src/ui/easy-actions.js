/* SPDX-License-Identifier: AGPL-3.0-or-later */
/* global Ext, Proxmox */
;(function () {
    const maxActions = 12;
    const maxSteps = 20;
    const maxSecrets = 24;
    const maxBindings = 8;
    const maxCommandBytes = 8192;
    const maxConfigBytes = 96 * 1024;
    const maxSecretBytes = 32 * 1024;
    const secretNamePattern = /^[A-Za-z][A-Za-z0-9_-]{0,47}$/;
    const envNamePattern = /^[A-Z_][A-Z0-9_]{0,63}$/;
    const reservedEnvNames = new Set([
        'ENV', 'SHELLOPTS', 'BASHOPTS', 'IFS', 'PATH', 'CDPATH', 'UID', 'EUID', 'PPID', 'GROUPS',
        'PWD', 'OLDPWD', 'GLOBIGNORE', 'PROMPT_COMMAND', '_',
    ]);

    function validateBindingEnv(value) {
        if (!envNamePattern.test(value)) {
            return 'Use up to 64 ASCII uppercase letters, digits or underscores. Start with a letter or underscore.';
        }
        if (reservedEnvNames.has(value) || /^(?:BASH_|LD_|DYLD_|EASY_ACTIONS_)/.test(value)) {
            return 'The shell or runner reserves this variable name.';
        }
        return true;
    }

    function byteLength(value) {
        return new TextEncoder().encode(value).length;
    }

    function request(url, method, data, success, failure, { redactError = false } = {}) {
        Proxmox.Utils.API2Request({
            url: method === 'DELETE' ? Ext.urlAppend(url, Ext.Object.toQueryString(data)) : url,
            method,
            jsonData: method === 'DELETE' ? undefined : data,
            success: (response) => success(response.result.data),
            failure: (response) => {
                if (redactError) {
                    failure(response.status);
                    return;
                }
                const result = response.result;
                const message = result && (result.message || result.errors)
                    ? Proxmox.Utils.extractRequestError(result, true)
                    : response.htmlStatus;
                failure(message || 'The request failed.');
            },
        });
    }

    function validateName(value) {
        const name = value.trim();
        if (!name.length || /[\p{Cc}\p{Cf}]/u.test(name)) {
            return 'Enter a name without control or formatting characters.';
        }
        return [...name].length <= 64 || 'Use up to 64 characters.';
    }

    function editRecord(title, fields, apply, { label = 'Apply', height } = {}) {
        const viewport = Ext.getBody().getViewSize();
        const form = Ext.create('Ext.form.Panel', {
            border: false,
            bodyPadding: 12,
            layout: height ? { type: 'vbox', align: 'stretch' } : 'anchor',
            scrollable: height ? 'y' : undefined,
            defaults: height ? { labelWidth: 120 } : { anchor: '100%', labelWidth: 120 },
            items: fields,
        });
        const dialog = Ext.create('Ext.window.Window', {
            title,
            modal: true,
            width: Math.min(590, viewport.width - 24),
            ...(height ? {
                height: Math.min(height, viewport.height - 24),
                minHeight: Math.min(300, viewport.height - 24),
            } : {}),
            layout: 'fit',
            items: [form],
            buttons: [
                {
                    text: 'Cancel',
                    handler: () => dialog.close(),
                },
                {
                    text: label,
                    handler: () => {
                        const editor = form.getForm();
                        if (editor.isValid()) {
                            apply(editor.getFieldValues());
                            dialog.close();
                        }
                    },
                },
            ],
        });
        dialog.show();
    }

    function nameField(value, validator = validateName) {
        return {
            xtype: 'textfield',
            name: 'name',
            fieldLabel: 'Name',
            value,
            allowBlank: false,
            validator,
        };
    }

    function editableGrid(layout, title, store, columns, handlers) {
        return Ext.create('Ext.grid.Panel', {
            ...layout,
            title,
            store,
            columns,
            sortableColumns: false,
            tbar: {
                overflowHandler: 'menu',
                items: [
                    { text: 'Add', itemId: 'add', handler: handlers.add },
                    { text: 'Edit', itemId: 'edit', disabled: true, handler: handlers.edit },
                    { text: 'Remove', itemId: 'remove', disabled: true, handler: handlers.remove },
                    ...(handlers.copy ? [{
                        text: 'Copy',
                        itemId: 'copy',
                        disabled: true,
                        tooltip: 'Copy the selected action and its bound secrets. Save edits to the action first.',
                        handler: handlers.copy,
                    }] : []),
                    ...(handlers.move ? [
                        '->',
                        { text: 'Up', itemId: 'up', disabled: true, handler: () => handlers.move(-1) },
                        { text: 'Down', itemId: 'down', disabled: true, handler: () => handlers.move(1) },
                    ] : []),
                ],
            },
            listeners: { itemdblclick: handlers.edit },
        });
    }

    function selectedRecord(grid) {
        return grid.getSelectionModel().getSelection()[0];
    }

    function updateGridButtons(grid, limit, enabled) {
        const store = grid.getStore();
        const record = selectedRecord(grid);
        const index = record ? store.indexOf(record) : -1;

        grid.down('#add').setDisabled(!enabled || store.getCount() >= limit);
        grid.down('#edit').setDisabled(index < 0);
        grid.down('#remove').setDisabled(index < 0);
        grid.down('#up')?.setDisabled(index < 1);
        grid.down('#down')?.setDisabled(index < 0 || index >= store.getCount() - 1);
    }

    function moveRecord(grid, offset) {
        const store = grid.getStore();
        const record = selectedRecord(grid);
        const index = record ? store.indexOf(record) + offset : -1;
        if (index >= 0 && index < store.getCount()) {
            store.remove(record);
            store.insert(index, record);
            grid.getSelectionModel().select(record);
        }
    }

    function showSecrets(url, guestID, metadata) {
        const store = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'updatedAt'],
        });
        let revision;
        let busy = false;

        const grid = Ext.create('Ext.grid.Panel', {
            store,
            border: false,
            columns: [
                { text: 'Name', dataIndex: 'name', flex: 1, renderer: Ext.String.htmlEncode },
                {
                    text: 'Last updated',
                    dataIndex: 'updatedAt',
                    width: 175,
                    renderer: (value) => Ext.String.htmlEncode(Proxmox.Utils.render_timestamp(value)),
                },
            ],
            tbar: [
                { text: 'Add', itemId: 'add', handler: () => editSecret() },
                { text: 'Rotate', itemId: 'rotate', disabled: true, handler: () => editSecret(selectedRecord(grid)) },
                { text: 'Delete', itemId: 'delete', disabled: true, handler: removeSecret },
                '->',
                { text: 'Reload', handler: reload },
            ],
        });
        const viewport = Ext.getBody().getViewSize();
        const dialog = Ext.create('Ext.window.Window', {
            title: `Secrets · Guest ${guestID}`,
            modal: true,
            width: Math.min(610, viewport.width - 24),
            height: Math.min(440, viewport.height - 24),
            layout: 'fit',
            items: [grid],
            listeners: { beforeclose: () => !busy },
            buttons: [{ text: 'Close', handler: () => dialog.close() }],
        });

        function updateButtons() {
            const record = selectedRecord(grid);
            grid.down('#add').setDisabled(store.getCount() >= maxSecrets);
            grid.down('#rotate').setDisabled(!record);
            grid.down('#delete').setDisabled(!record);
        }

        function updateMetadata(data, selectedName) {
            revision = data.revision;
            grid.getSelectionModel().deselectAll();
            store.loadData(data.secrets.map(({ name, updatedAt }) => ({ name, updatedAt })));
            const row = selectedName && store.findRecord('name', selectedName, 0, false, true, true);
            if (row) {
                grid.getSelectionModel().select(row);
            }
            updateButtons();
        }

        function setBusy(state, label) {
            busy = state;
            dialog.setLoading(state ? label : false);
        }

        function reload() {
            if (busy) {
                return;
            }
            const selectedName = selectedRecord(grid)?.get('name');
            setBusy(true, 'Loading secrets…');
            request(url, 'GET', undefined, (data) => {
                setBusy(false);
                updateMetadata(data, selectedName);
            }, (message) => {
                setBusy(false);
                Ext.Msg.alert('Could not load secrets', message);
            });
        }

        function editSecret(record) {
            if (busy) {
                return;
            }
            const name = record?.get('name');
            const operation = name ? 'Rotate' : 'Create';
            const fields = name ? [] : [nameField('', (value) => {
                if (!secretNamePattern.test(value)) {
                    return 'Use up to 48 ASCII letters, digits, underscores or hyphens. Start with a letter.';
                }
                const exists = store.findRecord('name', value, 0, false, true, true);
                return exists ? 'A secret with that name already exists. Use Rotate to replace its value.' : true;
            })];
            fields.push({
                xtype: 'textareafield',
                name: 'value',
                fieldLabel: name ? 'New value' : 'Value',
                height: 200,
                allowBlank: false,
                inputAttrTpl: 'autocomplete="off" autocapitalize="off" autocorrect="off" spellcheck="false"',
                fieldStyle: 'font-family: monospace',
                validator: (value) => {
                    if (!value.length || value.includes('\u0000')) {
                        return 'Enter a value without null characters.';
                    }
                    return byteLength(value) <= maxSecretBytes || 'The value exceeds 32 KiB.';
                },
            });
            const title = name ? `Rotate ${Ext.String.htmlEncode(name)}` : 'Create secret';
            editRecord(title, fields, (values) => {
                const secretName = name || values.name;
                setBusy(true, name ? 'Rotating secret…' : 'Creating secret…');
                request(url, 'PUT', { revision, name: secretName, value: values.value }, (data) => {
                    setBusy(false);
                    updateMetadata(data, secretName);
                }, (status) => {
                    setBusy(false);
                    const message = Number(status) === 409
                        ? 'The secrets list changed. Reload the list and enter the value again.'
                        : 'Check the name, value and available secret slots, then enter the value again.';
                    Ext.Msg.alert(`Could not ${operation.toLowerCase()} secret`, message);
                }, { redactError: true });
            }, { label: operation });
        }

        function removeSecret() {
            const name = selectedRecord(grid)?.get('name');
            if (busy || !name) {
                return;
            }
            Ext.Msg.confirm('Delete secret', `Delete ${Ext.String.htmlEncode(name)}? Remove any action bindings first.`, (answer) => {
                if (answer === 'yes') {
                    setBusy(true, 'Deleting secret…');
                    request(url, 'DELETE', { revision, name }, (data) => {
                        setBusy(false);
                        updateMetadata(data);
                    }, (message) => {
                        setBusy(false);
                        Ext.Msg.alert('Could not delete secret', message);
                    });
                }
            });
        }

        grid.getSelectionModel().on('selectionchange', updateButtons);
        updateMetadata(metadata);
        dialog.show();
    }

    function copyStep({ name, command, timeout }) {
        return { name, command, timeout };
    }

    const bashKeywords = new Set([
        'if', 'then', 'elif', 'else', 'fi', 'case', 'esac', 'for', 'select', 'while', 'until',
        'in', 'do', 'done', 'function', 'time', 'coproc',
    ]);
    const bashBuiltins = new Set([
        'alias', 'break', 'cd', 'command', 'continue', 'declare', 'echo', 'eval', 'exec', 'exit',
        'export', 'false', 'getopts', 'local', 'mapfile', 'printf', 'pwd', 'read', 'readonly', 'return',
        'set', 'shift', 'shopt', 'source', 'test', 'trap', 'true', 'type', 'ulimit', 'umask', 'unset', 'wait',
    ]);
    const bashEscape = /\\[\s\S]/.source;
    const bashVariable = /\$(?:\{[^}\n]*\}|[a-zA-Z_]\w*|[0-9?#$!*@-])/.source;
    const bashWordStart = /(?<![^ \t\n;|&()<>])/.source;
    const bashTokens = new RegExp([
        bashEscape,
        `${bashWordStart}(?<comment>#[^\\n]*)`,
        /(?<literal>\$'(?:\\[\s\S]|[^'\\])*'?|'[^']*'?)/.source,
        /(?<string>\$?"(?:\\[\s\S]|[^"\\])*"?)/.source,
        `(?<variable>${bashVariable})`,
        `${bashWordStart}${/(?<word>[a-zA-Z_]\w*)(?=$|[ \t\n;|&()<>=])/.source}`,
        /(?<operator>\[\[|\]\]|[|&;<>!(){}])/.source,
        /(?<number>(?<![\w.-])\d+(?![\w.-]))/.source,
    ].join('|'), 'g');
    const bashInterpolations = new RegExp(`${bashEscape}|(?<variable>${bashVariable})`, 'g');

    function highlightBash(context, source, colors) {
        function append(text, color) {
            if (!text) {
                return;
            }
            if (!color) {
                context.append(text);
                return;
            }
            const span = context.ownerDocument.createElement('span');
            span.style.color = color;
            span.textContent = text;
            context.append(span);
        }

        function appendString(value) {
            let offset = 0;
            for (const match of value.matchAll(bashInterpolations)) {
                if (match.groups.variable) {
                    append(value.slice(offset, match.index), colors.string);
                    append(match[0], colors.variable);
                    offset = match.index + match[0].length;
                }
            }
            append(value.slice(offset), colors.string);
        }

        let offset = 0;
        for (const match of source.matchAll(bashTokens)) {
            append(source.slice(offset, match.index));
            const kind = Object.keys(match.groups).find((name) => match.groups[name] !== undefined);
            if (kind === 'string') {
                appendString(match[0]);
            } else if (kind === 'word') {
                const word = match[0];
                const color = bashKeywords.has(word) ? colors.keyword : bashBuiltins.has(word) ? colors.builtin : '';
                append(word, color);
            } else {
                append(match[0], colors[kind === 'literal' ? 'string' : kind]);
            }
            offset = match.index + match[0].length;
        }
        append(source.slice(offset));
    }

    function attachBashHighlight(field) {
        if (window.matchMedia('(forced-colors: active)').matches) {
            return;
        }
        const input = field.inputEl.dom;
        const wrapper = input.parentElement;
        const inputStyle = window.getComputedStyle(input);
        const foreground = inputStyle.color;
        const [red, green, blue] = foreground.match(/[\d.]+/g)?.map(Number) ?? [];
        const colors = red * 0.2126 + green * 0.7152 + blue * 0.0722 > 128 ? {
            comment: '#a1afc0', string: '#91dda9', variable: '#a5d4fe', keyword: '#d4afff',
            builtin: '#80d8e7', operator: '#ffb387', number: '#f0ce8c',
        } : {
            comment: '#57606a', string: '#116329', variable: '#0550ae', keyword: '#6639ba',
            builtin: '#0b5c75', operator: '#953800', number: '#795104',
        };

        // Mirror the native textarea so editing, form validation and keyboard shortcuts stay native.
        const overlay = input.ownerDocument.createElement('pre');
        overlay.setAttribute('aria-hidden', 'true');
        Object.assign(overlay.style, {
            boxSizing: 'border-box',
            position: 'absolute',
            margin: '0',
            border: '0',
            background: 'transparent',
            overflow: 'hidden',
            pointerEvents: 'none',
            zIndex: '1',
            color: foreground,
            fontFamily: inputStyle.fontFamily,
            fontSize: inputStyle.fontSize,
            fontStyle: inputStyle.fontStyle,
            fontWeight: inputStyle.fontWeight,
            fontVariantLigatures: inputStyle.fontVariantLigatures,
            lineHeight: inputStyle.lineHeight,
            direction: inputStyle.direction,
            textAlign: inputStyle.textAlign,
            letterSpacing: inputStyle.letterSpacing,
            wordSpacing: inputStyle.wordSpacing,
            whiteSpace: inputStyle.whiteSpace,
            overflowWrap: inputStyle.overflowWrap,
            tabSize: inputStyle.tabSize,
            padding: inputStyle.padding,
        });
        if (window.getComputedStyle(wrapper).position === 'static') {
            wrapper.style.position = 'relative';
        }
        wrapper.append(overlay);
        input.style.caretColor = foreground;
        const nativeColor = input.style.color;

        function syncScroll() {
            overlay.scrollTop = input.scrollTop;
            overlay.scrollLeft = input.scrollLeft;
        }

        function syncLayout() {
            const inputRect = input.getBoundingClientRect();
            const wrapperRect = wrapper.getBoundingClientRect();
            Object.assign(overlay.style, {
                top: `${inputRect.top - wrapperRect.top - wrapper.clientTop + input.clientTop}px`,
                left: `${inputRect.left - wrapperRect.left - wrapper.clientLeft + input.clientLeft}px`,
                width: `${input.clientWidth}px`,
                height: `${input.clientHeight}px`,
            });
            syncScroll();
        }

        let composing = false;
        let highlighted;
        function render() {
            const source = input.value;
            const enabled = !composing && source.length <= maxCommandBytes;
            overlay.hidden = !enabled;
            input.style.color = enabled ? 'transparent' : nativeColor;
            if (!enabled) {
                return;
            }
            if (source !== highlighted) {
                const content = input.ownerDocument.createDocumentFragment();
                highlightBash(content, source, colors);
                if (source.endsWith('\n')) {
                    content.append('\u200b');
                }
                overlay.replaceChildren(content);
                highlighted = source;
            }
            syncLayout();
        }

        const resize = new ResizeObserver(syncLayout);
        resize.observe(input);
        field.on('beforedestroy', () => resize.disconnect());
        field.on('change', render);
        input.addEventListener('input', render);
        input.addEventListener('scroll', syncScroll);
        input.addEventListener('compositionstart', () => {
            composing = true;
            render();
        });
        input.addEventListener('compositionend', () => {
            composing = false;
            render();
        });
        render();
    }

    function copyBinding({ name, env, mode }) {
        return { name, env, mode };
    }

    function copyAction({ name, steps, secrets }) {
        return {
            name,
            steps: steps.map(copyStep),
            ...(secrets?.length ? { secrets: secrets.map(copyBinding) } : {}),
        };
    }

    function showConfig(url, guestID, config) {
        const actionStore = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'steps', 'secrets'],
            data: config.actions.map(copyAction),
        });
        const stepStore = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'command', 'timeout'],
        });
        const bindingStore = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: ['name', 'env', 'mode'],
        });
        const nameColumn = { text: 'Name', dataIndex: 'name', flex: 1, renderer: Ext.String.htmlEncode };
        let dirty = false;
        let saving = false;
        let closing = false;
        let loadingBindings = false;
        let actionCopyDialog;
        const savedActions = new Map(actionStore.getRange().map((record) => [
            record, JSON.stringify(copyAction(record.getData())),
        ]));

        function isSavedAction(record) {
            return record && savedActions.get(record) === JSON.stringify(copyAction(record.getData()));
        }

        function updateCopyButton() {
            actions.down('#copy').setDisabled(saving || !isSavedAction(selectedRecord(actions)));
        }

        function copySelectedAction() {
            const record = selectedRecord(actions);
            if (saving || !isSavedAction(record) || (actionCopyDialog && !actionCopyDialog.destroyed)) {
                return;
            }
            actionCopyDialog = showCopy(url, guestID, { name: record.get('name'), sourceRevision: config.revision });
        }

        function markDirty() {
            dirty = true;
            dialog.down('#save-actions').setDisabled(false);
            updateCopyButton();
        }

        function editAction(record) {
            function validateActionName(value) {
                const valid = validateName(value);
                if (valid !== true) {
                    return valid;
                }
                const name = value.trim().toLowerCase();
                if (name === 'config' || name === 'history') {
                    return 'This name is reserved.';
                }
                const duplicate = actionStore.getRange().some((item) =>
                    item !== record && item.get('name').toLowerCase() === name,
                );
                return duplicate ? 'An action with that name already exists.' : true;
            }

            editRecord(record ? 'Edit action' : 'Add action', [
                nameField(record ? record.get('name') : '', validateActionName),
            ], (values) => {
                const name = values.name.trim();
                if (record) {
                    record.set('name', name);
                } else {
                    actions.getSelectionModel().select(actionStore.add({ name, steps: [] })[0]);
                }
                markDirty();
            });
        }

        // The selected action owns its steps. Copy the visible list back after each edit.
        function saveSteps() {
            const action = selectedRecord(actions);
            action.set('steps', stepStore.getRange().map((step) => copyStep(step.getData())));
            updateGridButtons(steps, maxSteps, true);
            markDirty();
        }

        function editStep(record) {
            editRecord(record ? 'Edit step' : 'Add step', [
                nameField(record ? record.get('name') : ''),
                {
                    xtype: 'numberfield',
                    name: 'timeout',
                    fieldLabel: 'Timeout (s)',
                    value: record ? record.get('timeout') : 300,
                    minValue: 1,
                    maxValue: 1800,
                    allowDecimals: false,
                    allowBlank: false,
                },
                {
                    xtype: 'textareafield',
                    name: 'command',
                    fieldLabel: 'Bash command',
                    value: record ? record.get('command') : '',
                    flex: 1,
                    minHeight: 96,
                    fieldStyle: 'font-family: monospace; font-variant-ligatures: none; line-height: 1.5; tab-size: 4',
                    inputAttrTpl: 'autocapitalize="off" autocorrect="off" spellcheck="false"',
                    allowBlank: false,
                    listeners: { afterrender: attachBashHighlight },
                    validator: (value) => {
                        if (!value.trim().length || value.includes('\u0000')) {
                            return 'Enter a Bash command without null characters.';
                        }
                        return byteLength(value) <= maxCommandBytes || 'The command exceeds 8 KiB.';
                    },
                },
            ], (values) => {
                values.name = values.name.trim();
                if (record) {
                    record.set(values);
                } else {
                    steps.getSelectionModel().select(stepStore.add(values)[0]);
                }
                saveSteps();
            }, { height: 420 });
        }

        function saveBindings() {
            const action = selectedRecord(actions);
            action.set('secrets', bindingStore.getRange().map((binding) => copyBinding(binding.getData())));
            updateGridButtons(bindings, maxBindings, true);
            markDirty();
        }

        function editBinding(record) {
            const action = selectedRecord(actions);
            if (loadingBindings || !action) {
                return;
            }
            loadingBindings = true;

            request(`${url}/secrets`, 'GET', undefined, (data) => {
                loadingBindings = false;
                if (dialog.destroyed || saving || selectedRecord(actions) !== action
                    || (record && !bindingStore.contains(record))) {
                    return;
                }

                const availableNames = data.secrets.map(({ name }) => name)
                    .filter((name) => secretNamePattern.test(name));
                const currentName = record?.get('name');
                if (!availableNames.length) {
                    Ext.Msg.alert('No secrets available', 'Create a secret from the Actions menu, then add a binding.');
                    return;
                }
                const missing = currentName && !availableNames.includes(currentName);

                editRecord(record ? 'Edit secret binding' : 'Add secret binding', [
                    {
                        xtype: 'combobox',
                        name: 'name',
                        fieldLabel: missing ? 'Replacement secret' : 'Secret',
                        store: availableNames,
                        value: missing ? '' : currentName || availableNames[0],
                        queryMode: 'local',
                        editable: false,
                        forceSelection: true,
                        allowBlank: false,
                    },
                    {
                        xtype: 'textfield',
                        name: 'env',
                        fieldLabel: 'Variable name',
                        value: record ? record.get('env') : '',
                        allowBlank: false,
                        validator: (value) => {
                            const valid = validateBindingEnv(value);
                            if (valid !== true) {
                                return valid;
                            }
                            const duplicate = bindingStore.getRange().some((binding) =>
                                binding !== record && binding.get('env') === value,
                            );
                            return duplicate ? 'This action already uses that variable name.' : true;
                        },
                    },
                    {
                        xtype: 'combobox',
                        name: 'mode',
                        fieldLabel: 'Expose as',
                        store: [['file', 'Temporary file path'], ['env', 'Value in environment']],
                        value: record ? record.get('mode') : 'file',
                        queryMode: 'local',
                        editable: false,
                        forceSelection: true,
                        allowBlank: false,
                    },
                ], (values) => {
                    if (record) {
                        record.set(values);
                    } else {
                        bindings.getSelectionModel().select(bindingStore.add(values)[0]);
                    }
                    saveBindings();
                });
            }, (message) => {
                loadingBindings = false;
                if (!dialog.destroyed) {
                    Ext.Msg.alert('Could not load secrets', message);
                }
            });
        }

        const actions = editableGrid({ region: 'west', width: '42%', split: true }, 'Actions', actionStore, [
            nameColumn,
            { text: 'Steps', width: 66, dataIndex: 'steps', renderer: (value) => value.length },
        ], {
            add: () => editAction(),
            edit: () => editAction(selectedRecord(actions)),
            copy: copySelectedAction,
            remove: () => {
                const action = selectedRecord(actions);
                Ext.Msg.confirm('Remove action', `Remove ${Ext.String.htmlEncode(action.get('name'))} and its steps?`, (answer) => {
                    if (answer === 'yes') {
                        actionStore.remove(action);
                        updateGridButtons(actions, maxActions, true);
                        markDirty();
                    }
                });
            },
            move: (offset) => {
                moveRecord(actions, offset);
                markDirty();
            },
        });
        const steps = editableGrid({}, 'Steps', stepStore, [
            { xtype: 'rownumberer' },
            { ...nameColumn },
            { text: 'Timeout (s)', dataIndex: 'timeout', width: 95 },
        ], {
            add: () => editStep(),
            edit: () => editStep(selectedRecord(steps)),
            remove: () => {
                stepStore.remove(selectedRecord(steps));
                saveSteps();
            },
            move: (offset) => {
                moveRecord(steps, offset);
                saveSteps();
            },
        });
        const bindings = editableGrid({}, 'Secret bindings', bindingStore, [
            { ...nameColumn, text: 'Secret' },
            { text: 'Variable', dataIndex: 'env', flex: 1, renderer: Ext.String.htmlEncode },
            { text: 'Mode', dataIndex: 'mode', width: 90, renderer: (value) => value === 'file' ? 'File path' : 'Value' },
        ], {
            add: () => editBinding(),
            edit: () => editBinding(selectedRecord(bindings)),
            remove: () => {
                bindingStore.remove(selectedRecord(bindings));
                saveBindings();
            },
        });

        actions.getSelectionModel().on('selectionchange', (_model, records) => {
            const action = records[0];
            // ExtJS adds record IDs to input objects. Give each grid its own copies.
            stepStore.loadData((action?.get('steps') || []).map(copyStep));
            bindingStore.loadData((action?.get('secrets') || []).map(copyBinding));
            updateGridButtons(actions, maxActions, true);
            updateCopyButton();
            updateGridButtons(steps, maxSteps, !!action);
            updateGridButtons(bindings, maxBindings, !!action);
        });
        steps.getSelectionModel().on('selectionchange', () => {
            updateGridButtons(steps, maxSteps, !!selectedRecord(actions));
        });
        bindings.getSelectionModel().on('selectionchange', () => {
            updateGridButtons(bindings, maxBindings, !!selectedRecord(actions));
        });

        const viewport = Ext.getBody().getViewSize();
        const hasPreviousActions = config.previousActions?.length > 0;
        const dialog = Ext.create('Ext.window.Window', {
            title: `Actions · Config · Guest ${guestID}`,
            modal: true,
            width: Math.min(960, viewport.width - 24),
            height: Math.min(560, viewport.height - 24),
            layout: 'border',
            defaults: { border: false },
            items: [
                actions,
                { xtype: 'tabpanel', region: 'center', items: [steps, bindings] },
                {
                    xtype: 'component',
                    region: 'south',
                    padding: 10,
                    html: 'Steps run in order as root inside the guest, each in its own Bash process. Secret bindings are available to every step of the selected action.',
                },
            ],
            listeners: {
                beforeclose: () => {
                    if (saving) {
                        return false;
                    }
                    if (dirty && !closing) {
                        Ext.Msg.confirm('Discard changes', 'Close without saving changes?', (answer) => {
                            if (answer === 'yes') {
                                closing = true;
                                dialog.close();
                            }
                        });
                        return false;
                    }
                    return true;
                },
            },
            buttons: [
                { text: 'Load previous actions', hidden: !hasPreviousActions, handler: loadPreviousActions },
                { text: 'Close', handler: () => dialog.close() },
                { text: 'Save', itemId: 'save-actions', disabled: true, handler: saveConfig },
            ],
        });

        function loadPreviousActions() {
            Ext.Msg.confirm(
                'Load previous actions',
                'The guest configuration changed. Confirm this is the same guest to replace the actions currently in the editor.',
                (answer) => {
                    if (answer === 'yes') {
                        actions.getSelectionModel().deselectAll();
                        actionStore.loadData(config.previousActions.map(copyAction));
                        actions.getSelectionModel().select(0);
                        markDirty();
                    }
                },
            );
        }

        function saveConfig() {
            if (saving || !dirty) {
                return;
            }
            const payload = actionStore.getRange().map((action) => copyAction(action.getData()));
            const emptyAction = payload.find((action) => action.steps.length === 0);
            if (emptyAction) {
                Ext.Msg.alert('Step required', `Add a step to ${Ext.String.htmlEncode(emptyAction.name)}.`);
                return;
            }
            const json = JSON.stringify(payload);
            if (byteLength(json) > maxConfigBytes) {
                Ext.Msg.alert('Configuration too large', 'The configuration exceeds 96 KiB. Move long commands to scripts in the guest.');
                return;
            }

            saving = true;
            updateCopyButton();
            dialog.setLoading('Saving actions…');
            request(url, 'PUT', { revision: config.revision, actions: json }, () => {
                saving = false;
                dirty = false;
                dialog.close();
            }, (message) => {
                saving = false;
                updateCopyButton();
                dialog.setLoading(false);
                Ext.Msg.alert('Could not save actions', message);
            });
        }

        dialog.show();
        if (actionStore.getCount()) {
            actions.getSelectionModel().select(0);
        }
        updateGridButtons(actions, maxActions, true);
        updateCopyButton();
        updateGridButtons(steps, maxSteps, !!selectedRecord(actions));
        updateGridButtons(bindings, maxBindings, !!selectedRecord(actions));
    }

    function showCopy(url, guestID, action) {
        const targetKind = action ? 'guest' : 'container';
        const store = Ext.create('Ext.data.Store', {
            autoDestroy: true,
            fields: [{ name: 'vmid', type: 'int' }, 'node', 'type', 'label'],
            sorters: ['vmid'],
        });
        const target = Ext.create('Ext.form.field.ComboBox', {
            itemId: 'copy-target',
            fieldLabel: action ? 'Target VM or CT' : 'Target container',
            labelWidth: 120,
            anchor: '100%',
            emptyText: 'Search by VMID, name or node',
            store,
            queryMode: 'local',
            anyMatch: true,
            forceSelection: true,
            allowBlank: false,
            valueField: 'vmid',
            displayField: 'label',
            listConfig: {
                emptyText: `No matching ${targetKind}s`,
                getInnerTpl: () => '{label:htmlEncode}',
            },
        });
        let busy = true;
        const dialog = Ext.create('Ext.window.Window', {
            title: action ? `Copy action · ${Ext.String.htmlEncode(action.name)}` : `Copy actions and secrets · CT ${guestID}`,
            modal: true,
            defaultFocus: '#copy-target',
            width: Math.min(580, Ext.getBody().getViewSize().width - 24),
            layout: 'fit',
            items: [{
                xtype: 'form',
                border: false,
                bodyPadding: 12,
                items: [
                    target,
                    ...(action ? [{
                        xtype: 'component',
                        margin: '8 0 0',
                        html: 'Adds the selected action and its bound secrets. Matching names get a suffix.',
                    }] : []),
                ],
                buttons: [
                    { text: 'Cancel', handler: () => dialog.close() },
                    { text: 'Copy', formBind: true, disabled: true, handler: checkTarget },
                ],
            }],
            listeners: { beforeclose: () => !busy },
        });

        function copyFailed(message) {
            busy = false;
            dialog.setLoading(false);
            Ext.Msg.alert(action ? 'Could not copy action' : 'Could not copy actions and secrets', message);
        }

        function checkTarget() {
            const record = target.findRecordByValue(target.getValue());
            if (busy || !record) {
                return;
            }
            const targetVmid = record.get('vmid');
            const targetNode = record.get('node');
            const targetType = record.get('type');
            const label = Ext.String.htmlEncode(record.get('label'));
            const targetUrl = `/nodes/${encodeURIComponent(targetNode)}/easy-actions/${targetType}/${targetVmid}/copy`;
            busy = true;
            dialog.setLoading(`Checking the target ${targetKind}…`);

            request(targetUrl, 'GET', undefined, (state) => {
                const copy = (mode) => {
                    const destination = { targetNode, targetVmid, revision: state.revision };
                    const route = action ? 'copy-action' : 'copy';
                    const params = action ? { ...action, ...destination, targetType } : { ...destination, mode };
                    dialog.setLoading(action ? 'Copying action and bound secrets…' : 'Copying actions and secrets…');
                    request(`${url}/${route}`, 'POST', params, () => {
                        busy = false;
                        dialog.close();
                        const subject = action ? 'The action and its bound secrets' : 'Actions and secrets';
                        Ext.Msg.alert('Copy complete', `${subject} were copied to ${label}.`);
                    }, copyFailed);
                };
                if (action) {
                    copy();
                    return;
                }
                if (!Number(state.occupied)) {
                    copy('empty');
                    return;
                }

                dialog.setLoading(false);
                Ext.Msg.show({
                    title: 'Target already has a configuration',
                    message: `${label} already has saved actions or secrets.<br><br>`
                        + '<b>Append</b> adds the copied actions after the existing actions and keeps existing secrets. '
                        + 'Matching names are renamed in the copied configuration.<br><br>'
                        + '<b>Overwrite</b> replaces all target actions and secrets.',
                    buttons: Ext.Msg.YESNOCANCEL,
                    buttonText: { yes: 'Append', no: 'Overwrite', cancel: 'Cancel' },
                    defaultFocus: '#cancel',
                    fn: (answer) => {
                        if (answer === 'yes' || answer === 'no') {
                            copy(answer === 'yes' ? 'append' : 'overwrite');
                        } else {
                            busy = false;
                        }
                    },
                });
            }, copyFailed);
        }

        dialog.show();
        dialog.setLoading(`Loading ${targetKind}s…`);
        request('/cluster/resources?type=vm', 'GET', undefined, (resources) => {
            const targets = resources.filter(({ type, vmid, node, template }) =>
                (type === 'lxc' || (action && type === 'qemu'))
                && node && Number(vmid) !== Number(guestID) && !Number(template),
            ).map(({ type, vmid, name, node }) => ({
                type, vmid, node, label: `${type === 'lxc' ? 'CT' : 'VM'} ${vmid}${name ? ` (${name})` : ''} · ${node}`,
            }));
            busy = false;
            dialog.setLoading(false);
            if (targets.length) {
                store.loadData(targets);
            } else {
                dialog.close();
                Ext.Msg.alert(`No target ${targetKind}`, `No other ${targetKind}s are available.`);
            }
        }, (message) => {
            busy = false;
            dialog.close();
            Ext.Msg.alert(`Could not load ${targetKind}s`, message);
        });
        return dialog;
    }

    function attachActions(panel, type) {
        const guest = panel.pveSelNode.data;
        const toolbar = panel.getDockedItems('toolbar[dock=top]')[0];
        if (Proxmox.UserName !== 'root@pam' || guest.template || !toolbar || toolbar.child('#proxmox-easy-actions')) {
            return;
        }

        const guestID = encodeURIComponent(guest.vmid);
        const url = `/nodes/${encodeURIComponent(guest.node)}/easy-actions/${type}/${guestID}`;
        let currentMenuRequest = 0;
        let loadingConfig = false;
        let loadingSecrets = false;
        let copyDialog;
        let starting = false;

        function confirmRun(name, revision) {
            const escapedName = Ext.String.htmlEncode(name);
            Ext.Msg.confirm('Run action', `Run ${escapedName} on guest ${guestID}?`, (answer) => {
                if (answer !== 'yes' || starting) {
                    return;
                }
                starting = true;
                request(`${url}/run`, 'POST', { name, revision }, (upid) => {
                    starting = false;
                    Ext.create('Proxmox.window.TaskViewer', { upid, autoShow: true });
                }, (message) => {
                    starting = false;
                    Ext.Msg.alert('Could not start action', message);
                });
            });
        }

        function openConfig() {
            if (loadingConfig) {
                return;
            }
            loadingConfig = true;
            request(url, 'GET', undefined, (config) => {
                loadingConfig = false;
                if (!panel.destroyed) {
                    showConfig(url, guestID, config);
                }
            }, (message) => {
                loadingConfig = false;
                if (!panel.destroyed) {
                    Ext.Msg.alert('Could not load configuration', message);
                }
            });
        }

        function openSecrets() {
            if (loadingSecrets) {
                return;
            }
            loadingSecrets = true;
            const secretsUrl = `${url}/secrets`;
            request(secretsUrl, 'GET', undefined, (metadata) => {
                loadingSecrets = false;
                if (!panel.destroyed) {
                    showSecrets(secretsUrl, guestID, metadata);
                }
            }, (message) => {
                loadingSecrets = false;
                if (!panel.destroyed) {
                    Ext.Msg.alert('Could not load secrets', message);
                }
            });
        }

        const utilityItems = [
            { text: 'Config', iconCls: 'fa fa-fw fa-cog', handler: openConfig },
            { text: 'Secrets', iconCls: 'fa fa-fw fa-key', handler: openSecrets },
        ];
        if (type === 'lxc') {
            utilityItems.push({
                text: 'Copy',
                iconCls: 'fa fa-fw fa-copy',
                handler: () => {
                    if (!copyDialog || copyDialog.destroyed) {
                        copyDialog = showCopy(url, guestID);
                    }
                },
            });
        }
        const utilityItemCount = utilityItems.length;

        function replaceActions(menu, items) {
            // Keep the utility items mounted while refreshing saved actions and their revision.
            menu.items.getRange().slice(utilityItemCount).forEach((item) => menu.remove(item, true));
            if (items.length) {
                menu.add('-');
                menu.add(items);
            }
        }

        function loadMenu(menu) {
            const requestID = ++currentMenuRequest;
            replaceActions(menu, [{ text: 'Loading…', disabled: true }]);
            request(url, 'GET', undefined, (config) => {
                if (menu.destroyed || requestID !== currentMenuRequest) {
                    return;
                }
                replaceActions(menu, config.actions.map(({ name }) => ({
                    text: Ext.String.htmlEncode(
                        name.toLowerCase() === 'secrets' || (type === 'lxc' && name.toLowerCase() === 'copy')
                            ? `Run ${name}` : name,
                    ),
                    iconCls: 'fa fa-fw fa-play',
                    handler: () => confirmRun(name, config.revision),
                })));
            }, () => {
                if (!menu.destroyed && requestID === currentMenuRequest) {
                    replaceActions(menu, [{ text: 'Could not load actions', disabled: true }]);
                }
            });
        }

        const helpIndex = panel.helpButton ? toolbar.items.indexOf(panel.helpButton) : -1;
        toolbar.insert(helpIndex < 0 ? toolbar.items.getCount() : helpIndex, {
            xtype: 'button',
            itemId: 'proxmox-easy-actions',
            text: 'Actions',
            iconCls: 'fa fa-bolt',
            menu: {
                items: utilityItems,
                listeners: { beforeshow: loadMenu },
            },
        });
    }

    Proxmox.Utils.override_task_descriptions({ easyactions: ['VM/CT', 'Run guest action'] });

    // Both guest panels already construct their normal toolbar in initComponent.
    Ext.define('ProxmoxEasyActions.QemuConfig', {
        override: 'PVE.qemu.Config',
        initComponent: function () {
            this.callParent(arguments);
            attachActions(this, 'qemu');
        },
    });
    Ext.define('ProxmoxEasyActions.LxcConfig', {
        override: 'PVE.lxc.Config',
        initComponent: function () {
            this.callParent(arguments);
            attachActions(this, 'lxc');
        },
    });
})();
