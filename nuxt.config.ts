export default defineNuxtConfig({
  compatibilityDate: '2026-03-05',
  devtools: { enabled: true },
  modules: ['@nuxt/ui'],
  css: ['~/assets/css/main.css'],

  runtimeConfig: {
    public: {
      appName: 'OSINT Dashboard'
    }
  },

  nitro: {
    preset: 'node-server'
  }
})