import { createRouter, createWebHistory } from 'vue-router'
import HomeView from '../views/UserInfoView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'home',
      component: HomeView,
    },
    {
      path: '/protectedResource',
      name: 'protectedResource',
      // route level code-splitting
      // this generates a separate chunk (About.[hash].js) for this route
      // which is lazy-loaded when the route is visited.
      component: () => import('../views/ProtectedResourceView.vue'),
    },
  ],
})

export default router
