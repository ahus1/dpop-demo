<script setup lang="ts">

import UserInfo from "@/components/UserInfo.vue";

</script>

<template>
  <main>
    <Suspense>
      <UserInfo />
      <template #fallback>
        Loading...
      </template>
    </Suspense>
  </main>
</template>
