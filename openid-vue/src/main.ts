import './assets/main.css'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'
import * as client from 'openid-client'
import * as clientWithState from './auth'

// Prerequisites

// Authorization server's Issuer Identifier URL
let server: URL = new URL('http://localhost:8080/realms/test')
let clientId: string = 'openid-vue'
// end of prerequisites

await clientWithState.init(server, clientId, () => {

    const app = createApp(App)

    app.use(router)

    app.mount('#app')

    // Remove authentication code response from URL
    router.push({ path: window.location.pathname })

});
